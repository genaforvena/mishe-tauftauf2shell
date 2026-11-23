set pagination off
set confirm off
set breakpoint pending on
set disable-randomization off
break ggml-rpc.cpp:2476
run
printf "=== HIT rdma_recv ===\n"
printf "cmd address: %p\n", &cmd
show environment
kill
quit
