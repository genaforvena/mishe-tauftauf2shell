set pagination off
set confirm off
set breakpoint pending on
set disable-randomization off
break ggml-rpc.cpp:2476
run
printf "=== HIT rdma_recv ===\n"
printf "cmd address: %p\n", &cmd
printf "rpc rbp: %p\n", $rbp
printf "saved rip slot: %p\n", $rbp+8
printf "server.buffers address: %p\n", &server.buffers
printf "sock address: %p\n", &sock
info proc mappings
bt 3
kill
quit
