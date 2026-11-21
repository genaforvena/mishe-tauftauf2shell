# Record the coupon buffer and live top-chunk address at the pinned memcpy,
# then let the service run its two mallocs and print the returned pointers.
set pagination off
set confirm off
break CouponList-internal.hpp:116
run
printf "GDB_HIT copy_site\n"
set $p = (unsigned char*) sketch->coupons_._M_impl._M_start
printf "GDB_COUPON_DATA=%p count=%u\n", $p, couponCount
printf "GDB_TOP_ADDR=%p\n", $p+32
printf "GDB_TOP_SIZE_BEFORE=0x%lx\n", *(unsigned long*)($p+40)
printf "GDB_SBRK_AT_COPY=%p\n", (void*)sbrk(0)
continue
printf "GDB_DONE\n"
