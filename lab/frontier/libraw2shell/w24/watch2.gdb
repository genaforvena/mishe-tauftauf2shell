set pagination off
set confirm off
set env MALLOC_TOP_PAD_ 16777216
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644
run -n 1 w13/dead-target.input
set $sf = (char*)main_arena.top + 8
disable 1
printf "W24X BASE off=%ld\n", (char*)$sf-(char*)destimage
break xtrans_demosaic.cpp:436
continue
set *(unsigned long*)$sf = 0x21001
watch *(unsigned short*)((char*)destimage + 68644*8)
break xtrans_demosaic.cpp:441
continue
printf "W24X STOP val=%#lx\n", *(unsigned long*)$sf
bt 4
quit
