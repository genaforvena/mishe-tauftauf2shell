# W191: does COPY1's out-of-bounds source clobber the unpacked buffer's
# next-chunk header at dst+2144 before the consumer frees it?
set pagination off
set confirm off
set $base = (long)outPtr
dump binary memory work-w191/hdr-before.bin $base+2144 $base+2160
break __memcpy_avx_unaligned_erms
continue
finish
dump binary memory work-w191/hdr-after.bin $base+2144 $base+2160
printf "HDR-BEFORE "
x/gx $base+2144
printf "HDR-AFTER "
x/gx $base+2144
continue
printf "FINISHED\n"
quit
