set pagination off
set $hit = 0
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644 && $hit++ == 0
run -n 1 evidence/nonzero-oob.input
printf "W9 MAPBASE destimage=%p reqend=%p\n", destimage, destimage+allocate_sz
info proc mappings
delete 1
continue
printf "W9 MAPFAULT idx=%d addr=%p\n", (row+top)*this->imgdata.sizes.width+col+left, $_siginfo._sifields._sigfault.si_addr
