set pagination off
set confirm off
set env MALLOC_TOP_PAD_ 16777216
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644
run -n 1 INPUT
set $sf = (char*)main_arena.top + 8
disable 1
printf "W24 BASE off=%ld sf=%p before=%#lx\n", (char*)$sf-(char*)destimage, $sf, *(unsigned long*)$sf
break xtrans_demosaic.cpp:436
continue
printf "W24 POSTLOOP val=%#lx top=%p image=%p destimage=%p\n", *(unsigned long*)$sf, main_arena.top, image, destimage
set *(unsigned long*)$sf = 0x21001
printf "W24 FORCED val=%#lx\n", *(unsigned long*)$sf
break LibRaw::border_interpolate
continue
printf "W24 BORDERENTRY val=%#lx top=%p image=%p\n", *(unsigned long*)$sf, main_arena.top, image
break xtrans_demosaic.cpp:441
continue
printf "W24 BORDEREXIT val=%#lx top=%p image=%p\n", *(unsigned long*)$sf, main_arena.top, image
break abort
continue
printf "W24 END val=%#lx top=%p\n", *(unsigned long*)$sf, main_arena.top
bt 5
quit
