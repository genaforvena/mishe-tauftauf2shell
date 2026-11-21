# Inspect the real glibc chunk header immediately after the 32-byte coupon
# vector, before and after the pinned library's memcpy at line 116.
set pagination off
set confirm off
break CouponList-internal.hpp:116
run
printf "GDB_HIT copy_site\n"
set $p = (unsigned char*) sketch->coupons_._M_impl._M_start
printf "GDB_COUPON_DATA=%p count=%u\n", $p, couponCount
printf "GDB_BEFORE chunk(p-16..p+48)\n"
x/9gx $p-16
next
printf "GDB_AFTER chunk(p-16..p+48)\n"
x/9gx $p-16
printf "GDB_AFTER payload(p+24..p+55)\n"
x/32bx $p+24
continue
printf "GDB_DONE\n"
