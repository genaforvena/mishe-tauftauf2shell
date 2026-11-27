#!/usr/bin/env ruby
# W349: does rb_str_casemap chaining produce a SECOND odd-capacity buffer and
# a second one-byte terminator write?  Single-byte case_map expands 2x
# (0xDF -> "SS") and writes two bytes while its guard is `to < to_end`;
# UTF-8 expands up to 3x (U+0390/U+03B0 -> 3 codepoints) with
# CASE_MAPPING_SLACK = 12.
#
# Shapes:
#   sb21       ISO-8859-1, 21 x 0xDF first buffer, capa = 21+20 = 41 (odd)
#   sb1041     same with 1041 bytes: first buffer saturates, chain follows
#   sb2100     same with 2100 bytes
#   sbmix1041  alternating ASCII and 0xDF: odd `to` parity in chained buffer
#   u03901041  UTF-8, 1041 x U+0390 (2 input bytes -> 6 output bytes)
#   u03b01041  UTF-8, 1041 x U+03B0
#   umix1041   UTF-8, alternating ASCII and U+0390
# Usage: RUBY script.rb SHAPE [upcase|fold|swapcase]
$stdout.sync = true
require 'digest'

shape = ARGV.fetch(0)
op = ARGV.fetch(1, 'upcase')

src = case shape
      when 'sb21'     then ("\xDF".b * 21).force_encoding('ISO-8859-1')
      when 'sb1041'   then ("\xDF".b * 1041).force_encoding('ISO-8859-1')
      when 'sb2100'   then ("\xDF".b * 2100).force_encoding('ISO-8859-1')
      when 'sbmix1041' then (("a\xDF".b * 520) + "a").force_encoding('ISO-8859-1')
      when 'u03901041' then ("\u0390" * 1041).freeze
      when 'u03b01041' then ("\u03B0" * 1041).freeze
      when 'umix1041'  then (("a\u0390" * 694)).freeze
      else abort "unknown shape #{shape.inspect}"
      end

out = case op
      when 'upcase'   then src.upcase
      when 'fold'     then src.downcase(:fold)
      when 'swapcase' then src.swapcase
      else abort "unknown op #{op.inspect}"
      end

puts "CHAIN shape=#{shape} op=#{op} in=#{src.bytesize} out=#{out.bytesize} " \
     "enc=#{out.encoding.name} sha=#{Digest::SHA256.hexdigest(out.b)[0, 16]}"
