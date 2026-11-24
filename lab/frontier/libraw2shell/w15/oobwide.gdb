set pagination off
set $hit = 0
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644 && $hit++ == 0
eval "run -n 1 %s", $inp
set $oob = (unsigned short *)((char *)destimage + allocate_sz)
delete 1
continue
printf "WIDE FAULT IDX=%d addr=%p\n", (row+top)*this->imgdata.sizes.width+col+left, $_siginfo._sifields._sigfault.si_addr
set $off = 0
while $off <= 40000
  printf "WIDE off=%d: ", $off
  set $i = 0
  while $i < 4
    printf "%hx ", $oob[$off + $i]
    set $i = $i + 1
  end
  printf "\n"
  set $off = $off + 1000
end
kill
