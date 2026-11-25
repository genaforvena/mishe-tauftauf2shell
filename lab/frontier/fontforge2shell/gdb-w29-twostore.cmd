set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
break fvimportbdf.c:1756
run -script /home/mesh-home/mishe-tauftauf2shell/lab/frontier/fontforge2shell/import-twostore.ff
printf "W29S1 i=%d glyph=%d tot=%d encs=%p value=%d word[-8]=%#x word[-4]=%#x\n", i, glyph, tot, encs, (i/(max2-min2+1)+min2)*256+(i%(max2-min2+1)+min1), *(unsigned int*)((char*)encs-8), *(unsigned int*)((char*)encs-4)
continue
printf "W29S2 i=%d glyph=%d tot=%d encs=%p value=%d word[-8]=%#x word[-4]=%#x\n", i, glyph, tot, encs, (i/(max2-min2+1)+min2)*256+(i%(max2-min2+1)+min1), *(unsigned int*)((char*)encs-8), *(unsigned int*)((char*)encs-4)
continue
printf "W29POST word[-8]=%#x word[-4]=%#x\n", *(unsigned int*)((char*)encs-8), *(unsigned int*)((char*)encs-4)
continue
quit
