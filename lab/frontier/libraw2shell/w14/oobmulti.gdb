set pagination off
set $hit = 0
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644 && $hit++ == 0
eval "run -n 1 %s", $inp
set $oob = (unsigned short *)((char *)destimage + allocate_sz)
delete 1
continue
printf "MULTI FAULT IDX=%d addr=%p\n", (row+top)*this->imgdata.sizes.width+col+left, $_siginfo._sifields._sigfault.si_addr
set $starts = {0, 4600, 10000, 16800}
set $s = 0
while $s < 4
  printf "MULTI off=%d: ", $starts[$s]
  set $i = 0
  while $i < 24
    printf "%hx ", $oob[$starts[$s] + $i]
    set $i = $i + 1
  end
  printf "\n"
  set $s = $s + 1
end
kill
