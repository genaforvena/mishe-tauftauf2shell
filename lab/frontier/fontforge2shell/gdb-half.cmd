set pagination off
break fvimportbdf.c:1751
commands
silent
printf "HIT i=%d glyph=%d encs=%p rhs=", i, glyph, encs
print (i/(max2-min2+1)+min2)*256+(i%(max2-min2+1)+min1)
continue
end
run -script import-half.ff
quit
