set pagination off
set confirm off
set $hit = 0
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644 && $hit++ == 0
set $i = 0
while $i < $nfiles
  set $hit = 0
  eval "run -n 1 %s", $files[$i]
  printf "GRID %s IDX=%d c0=%d c1=%d c2=%d den=%d black=%d white=%d\n", $files[$i], (row+top)*this->imgdata.sizes.width+col+left, avg[0]/avg[3], avg[1]/avg[3], avg[2]/avg[3], avg[3], this->imgdata.color.dng_levels.dng_black, this->imgdata.color.dng_levels.dng_whitelevel[0]
  kill
  set $i = $i + 1
end
