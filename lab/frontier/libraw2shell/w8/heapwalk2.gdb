set pagination off
set $hit = 0
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 268324 && $hit++ == 0
run -n 1 evidence/dim1024-wl24601.input
set $base = (char *)destimage
set $sz0 = *(unsigned long *)($base-8) & ~7
set $end = $base + allocate_sz
set $heapend = (char *)0x555555968000
printf "W8 BASE=%p REQEND=%p CHUNKSZ=%lu CHUNKEND=%p HEAPEND=%p GAP=%lu\n", $base, $end, $sz0, $base+$sz0, $heapend, $heapend-($base+$sz0)
set $p = $base + $sz0
set $n = 0
while $p < $heapend && $n < 60
  set $h = *(unsigned long *)($p-8)
  set $sz = $h & ~7
  printf "W8 CHUNK %02d ptr=%p size=%lu flags=%lx\n", $n, $p, $sz, $h & 7
  if $sz < 16 || $sz > 1000000000
    printf "W8 BADHDR at %p\n", $p
    set $p = $heapend
  else
    set $p = $p + $sz
  end
  set $n = $n + 1
end
