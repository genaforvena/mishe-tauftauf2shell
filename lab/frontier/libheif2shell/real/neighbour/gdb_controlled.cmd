# gdb batch probe for the W166 controlled-row input on the retained-frame
# driver. Usage (from repo root):
# gdb -q -batch -x lab/frontier/libheif2shell/real/neighbour/gdb_controlled.cmd \
#   /tmp/libheif2shell-reencode-retain > EVIDENCE 2>&1
set pagination off
set confirm off
set print pretty off
break calloc if $rsi == 32783
run lab/frontier/libheif2shell/real/neighbour/controlled-size.heif /tmp/libheif-controlled-out.heif
finish
continue
finish
set $p = $rax
printf "PLANE=%p\n", $p
printf "--- plane chunk header ---\n"
x/2gx $p-16
printf "--- offset 32768..32832 BEFORE ---\n"
x/8gx $p+32768
break __memcpy_avx_unaligned_erms if $rdx == 64 && $rdi >= $p+32768
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
