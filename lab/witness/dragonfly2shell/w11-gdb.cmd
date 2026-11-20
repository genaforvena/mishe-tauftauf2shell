set pagination off
set confirm off
set breakpoint pending on
break memcpy if $rdx == 20000
run --port 17389 --memcached_port 17221 --dir /tmp/w11-dfly-gdb-data --proactor_threads=2 --force_epoll
printf "MEMCPY_HIT dest=%p src=%p len=%ld rip=%p\n", $rdi, $rsi, $rdx, $rip
bt 12
x/16bx $rsi
shell sleep 10
