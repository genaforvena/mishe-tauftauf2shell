set pagination off
set $hit = 0
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 268324 && $hit++ == 0
run -n 1 evidence/dim1024-wl24601.input
printf "W9 FIRST IDX=%d destimage=%p alloc=%lld\n", (row+top)*this->imgdata.sizes.width+col+left, destimage, allocate_sz
delete 1
continue
printf "W9 FAULT IDX=%d addr=%p\n", (row+top)*this->imgdata.sizes.width+col+left, $_siginfo._sifields._sigfault.si_addr
bt 2
