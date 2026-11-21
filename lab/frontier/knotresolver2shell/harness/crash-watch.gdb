# No breakpoints: let the inferior run; a chosen-pointer dereference stops it.
set pagination off
set confirm off
cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
printf "STOP: rip=%p\n", $pc
info registers rip rdi rsi
bt 14
