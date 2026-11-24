set pagination off
set $hit = 0
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644 && $hit++ == 0
run -n 1 evidence/nonzero-oob.input
set $base = (char *)destimage
set $sz0 = *(unsigned long *)($base-16) & ~7
printf "W9 BASE=%p REQEND=%p CHUNKHDR-16=%lx CHUNKHDR-8=%lx\n", $base, $base+allocate_sz, *(unsigned long *)($base-16), *(unsigned long *)($base-8)
set $p = $base + allocate_sz
set $n = 0
while $n < 8
  set $h = *(unsigned long *)($p-8)
  printf "W9 NEXT %02d ptr=%p rawhdr=%lx\n", $n, $p, $h
  if ($h & ~7) < 16 || ($h & ~7) > 1000000000
    set $n = 8
  else
    set $p = $p + ($h & ~7)
  end
  set $n = $n + 1
end
