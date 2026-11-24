set pagination off
set $hit = 0
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 268324 && $hit++ == 0
run -n 1 evidence/dim1024-wl24601.input
set $base = (char *)destimage
set $end = $base + allocate_sz
set $heapend = (char *)0x555555968000
printf "W8 BASE=%p END=%p HEAPEND=%p ALLOC=%lld\n", $base, $end, $heapend, allocate_sz
printf "W8 DESTHDR size=%lu flags=%lx\n", *(unsigned long *)($base-8) & ~7, *(unsigned long *)($base-8) & 7
set $p = $end
set $n = 0
while $p < $heapend && $n < 40
  set $h = *(unsigned long *)($p-8)
  set $sz = $h & ~7
  printf "W8 CHUNK %02d ptr=%p size=%lu flags=%lx\n", $n, $p, $sz, $h & 7
  if $sz < 16
    set $p = $heapend
  else
    set $p = $p + $sz
  end
  set $n = $n + 1
end
delete 1
continue
printf "W8 FAULT IDX=%d row=%d col=%d top=%d left=%d addr=%p\n", (row+top)*this->imgdata.sizes.width+col+left, row, col, top, left, $_siginfo._sifields._sigfault.si_addr
bt 3
