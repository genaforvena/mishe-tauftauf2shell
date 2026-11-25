set pagination off
set confirm off
set env MALLOC_TOP_PAD_ 4194304
set $idxlo = IDXLO
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= $idxlo
run -n 1 INPUT
printf "W21 FIRST IDX=%d w=%d h=%d destimage=%p alloc=%lld\n", (row+top)*this->imgdata.sizes.width+col+left, this->imgdata.sizes.width, this->imgdata.sizes.height, destimage, allocate_sz
set $szfield = main_arena.top + 8
printf "W21 top=%p sizefield=%p off=%ld idx=%ld mod4=%ld usable=%lu\n", main_arena.top, $szfield, (char*)$szfield-(char*)destimage, ((char*)$szfield-(char*)destimage)/8, (((char*)$szfield-(char*)destimage)/8)%4, (unsigned long)malloc_usable_size((void*)destimage)
printf "W21 sizefield_now=%#lx size=%lu system_mem=%lu\n", *(unsigned long*)$szfield, *(unsigned long*)$szfield & ~(unsigned long)7, main_arena.system_mem
printf "W21 halfwords_at_sizefield=%04x %04x %04x %04x\n", *(unsigned short*)$szfield, *(unsigned short*)($szfield+2), *(unsigned short*)($szfield+4), *(unsigned short*)($szfield+6)
