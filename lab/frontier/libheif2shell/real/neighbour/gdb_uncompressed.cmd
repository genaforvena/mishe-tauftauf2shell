# W178: read the OOB source row on the uncompressed-codec -> x265 padding path.
# Usage (from repo root):
# gdb -q -batch -x lab/frontier/libheif2shell/real/neighbour/gdb_uncompressed.cmd \
#   /tmp/w178-reencode-unci > EVIDENCE 2>&1
set pagination off
set confirm off
set print pretty off
set environment SYNTH_FIRST 1
set environment TW 512
set environment TH 64
break calloc if $rsi >= 32760 && $rsi <= 32800
run /tmp/w178-unci-both.heif /tmp/w178-unci-gdb-out.heif
finish
continue
finish
set $p = $rax
printf "PLANE=%p\n", $p
printf "--- plane chunk header ---\n"
x/2gx $p-16
printf "--- offset 32768..32832 BEFORE ---\n"
x/8gx $p+32768
break __memcpy_avx_unaligned_erms if $rdx == 64 && $rdi >= $p+32768 && $rdi < $p+40000
continue
printf "OOB dest_off=%ld src=%p\n", $rdi-$p, $rsi
x/8gx $rsi
x/64bx $rsi
continue
printf "--- offset 32768..32832 AFTER ---\n"
x/8gx $p+32768
printf "STOP rip=%p\n", $rip
bt 5
quit
