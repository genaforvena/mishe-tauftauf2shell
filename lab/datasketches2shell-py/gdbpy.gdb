set pagination off
set breakpoint pending on
set print pretty off
break CouponList-internal.hpp:116
run
set $p = (char*) sketch->coupons_.data()
printf "HIT couponCount=%d p=%p\n", couponCount, $p
x/4gx $p+32
printf "BEFORE\n"
next
printf "AFTER\n"
x/4gx $p+32
continue
bt 12
