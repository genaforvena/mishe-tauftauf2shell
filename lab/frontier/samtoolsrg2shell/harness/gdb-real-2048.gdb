set pagination off
set confirm off
set environment LD_LIBRARY_PATH work/htslib-plain/lib
break bam_plcmd.c:1299
run mpileup -G inputs/rg-2048.bin
printf "BUF_ADDRESS=%p\n", &buf
x/32bx buf+1024
printf "RBP=%p\n", $rbp
x/gx $rbp+8
bt 8
continue
