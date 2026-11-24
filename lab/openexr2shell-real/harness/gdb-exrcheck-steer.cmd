# W181: observe the two inverse-sort copies at internal_zstd.c:472 in the
# UNMODIFIED upstream exrcheck -c binary. The breakpoint on
# sort2_4ByteChannels_tiled and the `run -c FILE` line are supplied by the
# calling script so this one file serves every forged N and fill byte.
set pagination off
set confirm off
set $outaddr = (long)outPtr
set $inaddr = (long)inPtr
printf "SINK-ENTER out=%p in=%p channels=%d height=%d in-out=%ld\n", outPtr, inPtr, channelsSize, height, (long)(inPtr-outPtr)
break __memcpy_avx_unaligned_erms
continue
set $dst1 = (long)$rdi
set $src1 = (long)$rsi
set $len1 = (long)$rdx
printf "COPY1 dst=%#lx src=%#lx len=%ld dst-out=%ld src-in=%ld\n", $dst1, $src1, $len1, $dst1-$outaddr, $src1-$inaddr
x/8bx $src1
x/8bx $dst1
bt 4
finish
x/8bx $dst1
continue
set $dst2 = (long)$rdi
set $src2 = (long)$rsi
set $len2 = (long)$rdx
printf "COPY2 dst=%#lx src=%#lx len=%ld dst-out=%ld src-in=%ld\n", $dst2, $src2, $len2, $dst2-$outaddr, $src2-$inaddr
x/16bx $src2
x/8bx $dst2
bt 4
finish
x/8bx $dst2
quit
