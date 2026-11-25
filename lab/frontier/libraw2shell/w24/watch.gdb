set pagination off
set confirm off
set env MALLOC_TOP_PAD_ 16777216
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644
run -n 1 w13/dead-target.input
set $sf = (char*)main_arena.top + 8
disable 1
printf "W24W BASE off=%ld sf=%p before=%#lx\n", (char*)$sf-(char*)destimage, $sf, *(unsigned long*)$sf
break xtrans_demosaic.cpp:436
continue
printf "W24W POSTLOOP val=%#lx\n", *(unsigned long*)$sf
set *(unsigned long*)$sf = 0x21001
watch *(unsigned long*)$sf
break xtrans_demosaic.cpp:441
continue
printf "W24W STOP val=%#lx pc=%s\n", *(unsigned long*)$sf, $pc
bt 4
quit
