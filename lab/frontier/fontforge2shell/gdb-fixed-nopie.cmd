set pagination off
break sfd.c:1671
run -script import-value-nonpie-a-nopie.ff
printf "FIXED enc=%d i=%d bfc->bitmap=%p\n", enc, i, bfc->bitmap
x/8bx bfc->bitmap
quit
