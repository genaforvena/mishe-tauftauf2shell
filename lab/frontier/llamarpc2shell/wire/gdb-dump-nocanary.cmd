set pagination off
set confirm off
set breakpoint pending on
break socket_t::impl::rdma_recv
run
printf "=== HIT rdma_recv ===\n"
finish
finish
finish
printf "cmd address: %p\n", &cmd
printf "rpc rbp: %p\n", $rbp
dump binary memory /home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/wire/evidence/pristine-nocanary.bin &cmd &cmd+4608
printf "=== mappings ===\n"
info proc mappings
kill
quit
