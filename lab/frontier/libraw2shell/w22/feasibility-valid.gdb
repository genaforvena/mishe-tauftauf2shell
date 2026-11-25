set pagination off
set confirm off
set env MALLOC_TOP_PAD_ 16777216
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644
run -n 1 ../w13/dead-target.input
set $sf = (char*)main_arena.top + 8
set $orig = *(unsigned long*)$sf
disable 1
printf "W22B BEFORE sf=%p val=%#lx top=%p\n", $sf, $orig, main_arena.top
break xtrans_demosaic.cpp:436
continue
printf "W22B AFTER val=%#lx\n", *(unsigned long*)$sf
set *(unsigned long*)$sf = 0x21001
printf "W22B CHOSEN val=%#lx\n", *(unsigned long*)$sf
break abort
continue
printf "W22B POST top=%p\n", main_arena.top
quit
