set pagination off
set confirm off
set env MALLOC_TOP_PAD_ 16777216
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644
run -n 1 ../w13/dead-target.input
set $sf = (char*)main_arena.top + 8
disable 1
printf "W21 BEFORE top=%p sf=%p off=%ld idx=%ld val=%#lx usable=%lu sysmem=%lu\n", main_arena.top, $sf, (char*)$sf-(char*)destimage, ((char*)$sf-(char*)destimage)/8, *(unsigned long*)$sf, (unsigned long)malloc_usable_size((void*)destimage), main_arena.system_mem
printf "W21 BEFORE hw=%04x %04x %04x %04x\n", *(unsigned short*)$sf, *(unsigned short*)($sf+2), *(unsigned short*)($sf+4), *(unsigned short*)($sf+6)
break xtrans_demosaic.cpp:436
continue
printf "W21 AFTER sf=%#lx hw=%04x %04x %04x %04x\n", *(unsigned long*)$sf, *(unsigned short*)$sf, *(unsigned short*)($sf+2), *(unsigned short*)($sf+4), *(unsigned short*)($sf+6)
break abort
continue
printf "W21 AT_ABORT sf=%#lx\n", *(unsigned long*)$sf
bt 5
