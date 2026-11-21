set breakpoint pending on
break jpeg_read_scanlines
run
set $row=*(unsigned char**)$rsi
printf "ROW=%p\n",$row
finish
printf "FIRST ROW bytes 0..63:\n"
x/64bx $row
printf "PAST END +128..+191 (as words, +176 is object start):\n"
x/8gx $row+128
printf "CHOSEN PTR at +184 (row+56): %lx\n",*(unsigned long*)($row+184)
printf "original word at +184 before: see below\n"
info symbol 0xa2d260
info symbol 0xa472c0
