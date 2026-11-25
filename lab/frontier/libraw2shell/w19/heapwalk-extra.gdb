set pagination off
set confirm off
set $hit = 0
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644 && $hit++ == 0
run -n 1 w13/dead-target.input
printf "W19 FIRST IDX=%d w=%d h=%d destimage=%p alloc=%lld\n", (row+top)*this->imgdata.sizes.width+col+left, this->imgdata.sizes.width, this->imgdata.sizes.height, destimage, allocate_sz
printf "W19 usable=%lu sizefield=%lx main_arena.top=%p\n", (unsigned long)malloc_usable_size((void *)destimage), *(unsigned long *)((char *)destimage-8), main_arena.top
set $u = (char *)destimage
set $n = 0
while $n < 16
  set $raw = *(unsigned long *)($u-8)
  set $sz = $raw & ~(unsigned long)7
  printf "W19 CHUNK %02d user=%p size=%lu flags=%lx is_top=%d\n", $n, $u, $sz, $raw & 7, (($u-16) == main_arena.top)
  if (($u-16) == main_arena.top) || ($sz < 32) || ($sz > 40000000)
    printf "W19 STOP at chunk %02d: user=%p destimage_end=%p\n", $n, $u, (char *)destimage+allocate_sz
    set $n = 16
  else
    set $u = $u + $sz
    set $n = $n + 1
  end
end
info proc mappings
