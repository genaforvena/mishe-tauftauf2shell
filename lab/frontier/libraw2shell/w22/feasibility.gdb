set pagination off
set confirm off
set env MALLOC_TOP_PAD_ 16777216
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644
run -n 1 ../w13/dead-target.input
set $sf = (char*)main_arena.top + 8
set $orig = *(unsigned long*)$sf
disable 1
printf "W22 BEFORE sf=%p val=%#lx top=%p\n", $sf, $orig, main_arena.top
break xtrans_demosaic.cpp:436
continue
printf "W22 AFTER val=%#lx\n", *(unsigned long*)$sf
set *(unsigned long*)$sf = $orig
printf "W22 REPAIRED val=%#lx\n", *(unsigned long*)$sf
break abort
continue
printf "W22 POST top=%p\n", main_arena.top
bt 6
