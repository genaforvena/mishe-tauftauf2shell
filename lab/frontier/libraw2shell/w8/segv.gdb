set pagination off
set $hit = 0
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 268324 && $hit++ == 0
run -n 1 evidence/dim1024-wl24601.input
printf "W8 FIRST IDX=%d w=%d h=%d destimage=%p alloc=%lld\n", (row+top)*this->imgdata.sizes.width+col+left, this->imgdata.sizes.width, this->imgdata.sizes.height, destimage, allocate_sz
info proc mappings
delete 1
continue
printf "W8 STOP PC=%p SIGADDR=%p\n", $rip, $_siginfo._sifields._sigfault.si_addr
bt 6
info proc mappings
