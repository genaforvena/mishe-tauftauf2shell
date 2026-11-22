# Same crash path as crash-watch.gdb, plus libc/system addresses for the
# labeled ASLR-off rung-5 attempt.  Loopback only; host sysctl untouched.
set pagination off
set confirm off
cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
printf "STOP: rip=%p\n", $pc
info registers rip rdi rsi
bt 14
printf "SYSTEM_ADDR=%p\n", &system
info sharedlibrary libc
