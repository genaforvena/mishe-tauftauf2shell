# Scan Ruby sources for an iseq that the 0x53/0x73 iseq_encoded[0] corruption
# can turn into a code-handler disclosure without an invalid call-data dispatch.
# The accepted parent shape is:
#   putself|putnil, one-word instruction, <suffix>, leave
# where suffix preserves the leaked handler word (or converts it with
# objtostring/anytostring). Children of each iseq are searched recursively.
require 'find'
patterns = [
  %w[leave], %w[dup leave], %w[nop leave], %w[dup pop leave],
  %w[putnil pop leave], %w[putself pop leave],
  %w[objtostring anytostring leave],
  %w[dup objtostring anytostring leave]
]
files = iseqs = matches = 0
walk = lambda do |iseq, path|
  iseqs += 1
  own = iseq.disasm.split(/^== disasm:/)[1]
  ops = own.lines.filter_map do |line|
    m = line.match(/^(\d+)\s+(\w+)/)
    [m[1].to_i, m[2]] if m
  end
  if ops[0] && [:putself, :putnil].include?(ops[0][1].to_sym) &&
     ops[1] && ops[1][0] == 1 && ops[2] && ops[2][0] == 2
    suffix = ops.map(&:last)[2..]
    if patterns.include?(suffix)
      matches += 1
      puts "MATCH file=#{path} ops=#{ops.inspect}\n#{own}"
    end
  end
  iseq.each_child { |child| walk.call(child, path) }
end
ARGV.each do |root|
  Find.find(root) do |path|
    next unless path.end_with?('.rb')
    files += 1
    begin
      walk.call(RubyVM::InstructionSequence.compile_file(path), path)
    rescue StandardError, SyntaxError
    end
  end
end
puts "files=#{files} iseqs=#{iseqs} matches=#{matches}"
