set pagination off
set $hit = 0
break xtrans_demosaic.cpp:427 if (row+top)*this->imgdata.sizes.width + col + left >= 68644 && $hit++ == 0
eval "run -n 1 %s", $inp
printf "RGBPROBE IDX=%d row=%d col=%d top=%d left=%d ndir=%d\n", (row+top)*this->imgdata.sizes.width+col+left, row, col, top, left, ndir
printf "RGBPROBE hm=%d,%d,%d,%d,%d,%d,%d,%d max=%d\n", hm[0],hm[1],hm[2],hm[3],hm[4],hm[5],hm[6],hm[7],max
printf "RGBPROBE d0=%d,%d,%d d1=%d,%d,%d d2=%d,%d,%d d3=%d,%d,%d\n", rgb[0][row][col][0],rgb[0][row][col][1],rgb[0][row][col][2], rgb[1][row][col][0],rgb[1][row][col][1],rgb[1][row][col][2], rgb[2][row][col][0],rgb[2][row][col][1],rgb[2][row][col][2], rgb[3][row][col][0],rgb[3][row][col][1],rgb[3][row][col][2]
printf "RGBPROBE raw0=%d,%d,%d,%d raw1=%d,%d,%d,%d\n", image[(row+top)*this->imgdata.sizes.width+col+left][0],image[(row+top)*this->imgdata.sizes.width+col+left][1],image[(row+top)*this->imgdata.sizes.width+col+left][2],image[(row+top)*this->imgdata.sizes.width+col+left][3], image[(row+top)*this->imgdata.sizes.width+col+left+1][0],image[(row+top)*this->imgdata.sizes.width+col+left+1][1],image[(row+top)*this->imgdata.sizes.width+col+left+1][2],image[(row+top)*this->imgdata.sizes.width+col+left+1][3]
printf "RGBPROBE avg=%d,%d,%d,%d\n", avg[0],avg[1],avg[2],avg[3]
kill
