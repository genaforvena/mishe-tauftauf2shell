set pagination off
set $hit = 0
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644 && $hit++ == 0
run -n 1 evidence/nonzero-oob.input
printf "W9 FIRST IDX=%d w=%d h=%d destimage=%p alloc=%lld\n", (row+top)*this->imgdata.sizes.width+col+left, this->imgdata.sizes.width, this->imgdata.sizes.height, destimage, allocate_sz
printf "W9 HDR raw=%lx size=%lu flags=%lx\n", *(unsigned long *)(destimage-8), *(unsigned long *)(destimage-8) & ~7, *(unsigned long *)(destimage-8) & 7
call (size_t)malloc_usable_size((void *)destimage)
call (void)malloc_stats()
info proc mappings
delete 1
continue
printf "W9 FAULT IDX=%d row=%d col=%d top=%d left=%d addr=%p pc=%p\n", (row+top)*this->imgdata.sizes.width+col+left, row, col, top, left, $_siginfo._sifields._sigfault.si_addr, $rip
bt 4
