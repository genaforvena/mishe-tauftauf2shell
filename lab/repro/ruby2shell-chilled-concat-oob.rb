# W330: adjacent chilled-string `String#<<` codepoint arm.  In Ruby 3.4.12
# rb_str_concat reads the receiver encoding and emits the chilled-string
# deprecation warning only inside str_independent/str_modifiable, i.e. after
# the encoding decision for some paths; 3.4.13 warns first and reads the
# encoding afterwards.  A Warning.warn (or to_int) callback is Ruby code and
# can change the receiver between those two points.
#
# This is an in-process experiment: no wire input, no debugger write, no
# marker, no ObjectSpace/maps read.  Usage:
#   ruby ruby2shell-chilled-concat-oob.rb <literal-file> <codepoint> <action>

Warning[:deprecated] = true
$hook = 0
$recv = nil
$receiver_enc = nil

Warning.singleton_class.prepend(Module.new do
  def warn(*msgs, **kw)
    $hook += 1
    case ENV['W330_ACTION']
    when 'enc16' then $recv.force_encoding('UTF-16LE')
    when 'enc32' then $recv.force_encoding('UTF-32LE')
    when 'enc8'  then $recv.force_encoding('ASCII-8BIT')
    when 'encus' then $recv.force_encoding('US-ASCII')
    when 'grow'  then $recv.replace('G' * 4096)
    when 'shrink' then $recv.slice!(1..-1)
    when 'swap'  then $recv.replace('S' * 64)
    end
    super
  end
end)

load ARGV[0]
$recv = $chilled
$receiver_enc = $recv.encoding.name
code = Integer(ARGV[1])
action = ENV['W330_ACTION'] || 'none'

rhs = if action == 'to_int'
        Object.new.tap do |o|
          o.define_singleton_method(:to_int) do
            $hook += 1
            $recv.force_encoding('UTF-16LE')
            code
          end
        end
      else
        code
      end

begin
  result = ($recv << rhs)
  bytes = result.bytes
  puts "RESULT enc0=#{$receiver_enc} code=0x#{code.to_s(16)} action=#{action} " \
       "hook=#{$hook} out=#{bytes.length} enc=#{result.encoding} " \
       "valid=#{result.valid_encoding?} tail=#{bytes.last(8).map { |b| '%02x' % b }.join}"
rescue => e
  puts "RESULT enc0=#{$receiver_enc} code=0x#{code.to_s(16)} action=#{action} " \
       "hook=#{$hook} raised=#{e.class}: #{e.message}"
end
