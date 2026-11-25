set pagination off
break sfd.c:1671 if bfc->bitmap == (uint8_t *) 0x5a4344
run -script import-value-nonpie-b-nopie.ff
printf "HIT enc=%d i=%d bfc=%p bfc->bitmap=%p pt=%p\n", enc, i, bfc, bfc->bitmap, pt
x/8bx bfc->bitmap
bt 3
quit
