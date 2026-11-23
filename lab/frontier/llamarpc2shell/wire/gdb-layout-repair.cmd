set pagination off
set confirm off
set breakpoint pending on
break ggml-rpc.cpp:2476
run
printf "=== HIT rdma_recv ===\n"
printf "cmd address: %p\n", &cmd
printf "rpc rbp: %p\n", $rbp
printf "server address: %p\n", &server
printf "server.buffers address: %p\n", &server.buffers
printf "server.buffers raw words:\n"
x/3gx &server.buffers
printf "sock address: %p\n", &sock
printf "req address: %p\n", &req
printf "rsp address: %p\n", &rsp
printf "saved rip slot: %p\n", $rbp+8
printf "offsets from cmd: buffers=%ld sock=%ld req=%ld rsp=%ld savedrip=%ld\n", (char*)&server.buffers-(char*)&cmd, (char*)&sock-(char*)&cmd, (char*)&req-(char*)&cmd, (char*)&rsp-(char*)&cmd, (char*)($rbp+8)-(char*)&cmd
x/40gx $rbp-128
dump binary memory /home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/wire/evidence/layout-repair.bin &cmd &cmd+900
bt 4
kill
quit
