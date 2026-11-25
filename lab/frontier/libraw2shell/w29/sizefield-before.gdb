set pagination off
set confirm off
set env MALLOC_TOP_PAD_ 16777216
python
import os
gdb.execute("set args -n 1 " + os.environ["W23_INPUT"])
end
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644
run
set $sf = (char*)main_arena.top + 8
printf "W29 BEFORE sf=%#lx val=%#lx hw=%04x %04x %04x %04x sysmem=%lu\n", $sf, *(unsigned long*)$sf, *(unsigned short*)$sf, *(unsigned short*)($sf+2), *(unsigned short*)($sf+4), *(unsigned short*)($sf+6), main_arena.system_mem
disable 1
continue
printf "W29 CONTINUED\n"
quit
