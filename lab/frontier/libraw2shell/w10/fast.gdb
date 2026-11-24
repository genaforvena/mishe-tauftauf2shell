set pagination off
set $hit = 0
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644 && $hit++ == 0
eval "run -n 1 %s", $inp
printf "FAST IDX=%d w=%d h=%d c0=%d c1=%d c2=%d den=%d black=%d white=%d avg=%d,%d,%d,%d\n", (row+top)*this->imgdata.sizes.width+col+left, this->imgdata.sizes.width, this->imgdata.sizes.height, avg[0]/avg[3], avg[1]/avg[3], avg[2]/avg[3], avg[3], this->imgdata.color.dng_levels.dng_black, this->imgdata.color.dng_levels.dng_whitelevel[0], avg[0], avg[1], avg[2], avg[3]
kill
