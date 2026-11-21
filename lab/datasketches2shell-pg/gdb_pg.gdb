set pagination off
set breakpoint pending on
directory /home/mesh-home/mishe-tauftauf2shell/lab/datasketches2shell-pg/v52/hll/include
set environment PGDATA=/home/mesh-home/mishe-tauftauf2shell/lab/datasketches2shell-pg/pgdata-gdb
break CouponList-internal.hpp:116
run
printf "GDB_HIT count=%lu\n", couponCount
set $p = sketch->coupons_.data()
printf "GDB_P=%p\n", $p
printf "GDB_CHUNK_SIZE_AT_P_MINUS_8=%lu\n", *(unsigned long*)((char*)$p-8)
printf "GDB_BEFORE_NEXT0=%p NEXT8=%p\n", *(unsigned long*)((char*)$p+32), *(unsigned long*)((char*)$p+40)
next
printf "GDB_AFTER_NEXT0=%p NEXT8=%p\n", *(unsigned long*)((char*)$p+32), *(unsigned long*)((char*)$p+40)
printf "GDB_AFTER_B0=%02x %02x %02x %02x\n", *(unsigned char*)($p+32), *(unsigned char*)($p+33), *(unsigned char*)($p+34), *(unsigned char*)($p+35)
bt 8
continue
