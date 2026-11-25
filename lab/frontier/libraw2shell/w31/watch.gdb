set pagination off
set confirm off
set env MALLOC_TOP_PAD_ 16777216
python
import os
gdb.execute("set args -n 1 " + os.environ["W31_INPUT"])
end
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644
run
set $dest = (unsigned long)destimage
set $sfp = (char*)main_arena.top + 8
printf "W31W START dest=%#lx sfp=%#lx sfval=%#lx cs=%#lx\n", $dest, $sfp, *(unsigned long*)$sfp, *(unsigned long*)((char*)$dest-8)
disable 1
watch -l *(unsigned long*)$sfp
watch -l *(unsigned long*)((char*)$dest-8)
continue
printf "W31W HIT1 sfval=%#lx cs=%#lx row=%d col=%d\n", *(unsigned long*)$sfp, *(unsigned long*)((char*)$dest-8), row, col
bt 5
disable 2
disable 3
break __libc_free if $rdi == $dest
continue
printf "W31W ATFREE sfval=%#lx cs=%#lx\n", *(unsigned long*)$sfp, *(unsigned long*)((char*)$dest-8)
quit
