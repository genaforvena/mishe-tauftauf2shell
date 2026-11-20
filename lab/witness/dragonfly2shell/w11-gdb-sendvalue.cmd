set pagination off
set confirm off
set breakpoint pending on
break facade::MCReplyBuilder::SendValue
run --port 17391 --memcached_port 17223 --dir /tmp/w11-dfly-gdb-data2 --proactor_threads=2 --force_epoll
printf "SENDVALUE_HIT rsi=%p rdx=%p rcx=%ld r8=%p r9=%ld\n", $rsi, $rdx, $rcx, $r8, $r9
bt 8
x/16bx $rdx
x/16bx $rsi
shell sleep 8
