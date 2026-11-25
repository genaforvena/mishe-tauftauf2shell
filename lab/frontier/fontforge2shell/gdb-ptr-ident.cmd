set pagination off
break fvimportbdf.c:1751
run -script import-value-probe.ff
printf "target word:\n"
x/4gx 0x555555c227f0
printf "as string:\n"
x/s 0x555555c227f0
printf "chunk at encs-240:\n"
x/4gx (char*)encs-240
quit
