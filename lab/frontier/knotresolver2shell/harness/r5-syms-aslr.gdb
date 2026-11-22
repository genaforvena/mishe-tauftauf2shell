# ASLR-ON control for the wake-12 rung-5 claim.  Identical inferior invocation
# to r5-syms.gdb except gdb does NOT disable randomization.  The payload still
# carries the ASLR-off absolute addresses, so this measures the cost of the
# missing address-acquisition step, not a patched wire primitive.
# Loopback only; host sysctl untouched.
set pagination off
set confirm off
set disable-randomization off
cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
printf "ASLR_ON_STOP: rip=%p\n", $pc
info registers rip rdi rsi
bt 8
printf "ASLR_ON_SYSTEM=%p\n", &system
info sharedlibrary libc
