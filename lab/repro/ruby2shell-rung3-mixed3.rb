# W357: three leading one-byte chars before the sharp-s run.
# Input len = N+3, capa = N+23, overflow slot R = capa+24 = N+47
# (N=27/43/59 -> R=74/90/106, all == 10 mod 16).
# Run: lab/build/plain/ruby-3.4.12-plain/bin/ruby <this> N
n = (ARGV[0] || 27).to_i
s = ("aaa".b + "\xDF".b * n)
s.force_encoding(Encoding::ISO_8859_1)
t = s.upcase
print "N=#{n} mixed3 upcase ok, out len=#{t.bytesize}\n"
3000.times { (Array.new(200) { "payload#{object_id}" }).join }
a = []
500.times { a << ("x" * 64) }
GC.start
print "N=#{n} mixed3 churn ok\n"
