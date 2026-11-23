set pagination off
set confirm off
set breakpoint pending on
break ggml-rpc.cpp:2476
run
printf "=== HIT rdma_recv ===\n"
printf "cmd address: %p\n", &cmd
printf "rpc rbp: %p\n", $rbp
dump binary memory /home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/wire/evidence/earlyret.bin &cmd &cmd+1300
bt 6
kill
quit
