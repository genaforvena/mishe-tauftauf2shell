# gdb batch probe: the single out-of-bounds row from the one-row input.
# Usage: generate /tmp/libheif-one-row.heif with make_one_row_sequence.py, then
# gdb -q -batch -x gdb_one_row.cmd /tmp/libheif2shell-reencode-plain
set pagination off
set confirm off
set print pretty off
break calloc if $rsi == 32783
run /tmp/libheif-one-row.heif /tmp/libheif-one-row-gdb-out.heif
# two 32783-byte callocs in this run: frame 0 plane, frame 1 replacement plane
finish
continue
finish
set $p = $rax
printf "PLANE=%p\n", $p
printf "--- plane chunk header at plane-16 ---\n"
x/2gx $p-16
printf "--- next chunk header BEFORE (prev_size, size, fd, bk) ---\n"
x/4gx $p+32768
break __memcpy_avx_unaligned_erms if $rdx == 64 && $rdi >= $p + 32768
continue
printf "OOB_ROW dest_off=%ld src=%p\n", $rdi-$p, $rsi
printf "source 64 bytes:\n"
x/64bx $rsi
printf "destination 64 bytes BEFORE:\n"
x/64bx $rdi
continue
printf "STOP rip=%p\n", $rip
printf "--- next chunk header AFTER ---\n"
x/4gx $p+32768
bt 5
quit
