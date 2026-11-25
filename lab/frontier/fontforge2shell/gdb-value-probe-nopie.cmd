set pagination off
break sfd.c:1671
run -script import-value-probe-nopie.ff
printf "PROBE enc=%d i=%d bfc->bitmap=%p pt=%p\n", enc, i, bfc->bitmap, pt
x/8bx bfc->bitmap
quit
