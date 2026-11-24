set pagination off
set $hit = 0
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644 && $hit++ == 0
eval "run -n 1 %s", $inp
printf "W10 FIRST IDX=%d dest=%p alloc=%lld avg=%d,%d,%d,%d black=%d white=%d\n", (row+top)*this->imgdata.sizes.width+col+left, destimage, allocate_sz, avg[0], avg[1], avg[2], avg[3], this->imgdata.color.dng_levels.dng_black, this->imgdata.color.dng_levels.dng_whitelevel[0]
set $oob = (unsigned short *)((char *)destimage + allocate_sz)
delete 1
continue
printf "W10 FAULT IDX=%d addr=%p\n", (row+top)*this->imgdata.sizes.width+col+left, $_siginfo._sifields._sigfault.si_addr
printf "W10 VAL first OOB: %hx %hx %hx %hx\n", $oob[0], $oob[1], $oob[2], $oob[3]
bt 2
