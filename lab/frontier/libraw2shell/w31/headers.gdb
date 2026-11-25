set pagination off
set confirm off
set env MALLOC_TOP_PAD_ 16777216
python
import os
gdb.execute("set args -n 1 " + os.environ["W31_INPUT"])
end
# First OOB store: capture destimage and the top-chunk size field BEFORE the
# loop reaches destimage index 68773 (that index is (char*)main_arena.top + 8).
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644
run
set $dest = (unsigned long)destimage
printf "W31A dest=%#lx cs=%#lx top=%#lx sf=%#lx sfval=%#lx hw=%04x %04x %04x %04x\n", $dest, *(unsigned long*)($dest-8), main_arena.top, (char*)main_arena.top+8, *(unsigned long*)((char*)main_arena.top+8), *(unsigned short*)((char*)main_arena.top+8), *(unsigned short*)((char*)main_arena.top+10), *(unsigned short*)((char*)main_arena.top+12), *(unsigned short*)((char*)main_arena.top+14)
disable 1
set $w31cs = *(unsigned long*)($dest-8)
set $w31nx = (char*)($dest-16) + ($w31cs & ~1UL)
printf "W31B dest=%#lx cs=%#lx next=%#lx nextsize=%#lx top=%#lx topsize=%#lx sfval=%#lx\n", $dest, $w31cs, $w31nx, *(unsigned long*)($w31nx+8), main_arena.top, *(unsigned long*)((char*)main_arena.top+8), *(unsigned long*)((char*)main_arena.top+8)
# Observe the actual glibc free(destimage) call and its caller chain.
break __libc_free if $rdi == $dest
continue
printf "W31C p=%#lx cs=%#lx nextsize=%#lx top=%#lx topsize=%#lx\n", $rdi, *(unsigned long*)($rdi-8), *((unsigned long*)((char*)($rdi-16)+(*(unsigned long*)($rdi-8) & ~1UL)+8)), main_arena.top, *(unsigned long*)((char*)main_arena.top+8)
bt 8
continue
printf "W31D continued\n"
quit
