set pagination off
set confirm off
set breakpoint pending on
break socket_t::impl::rdma_recv
run
printf "=== HIT rdma_recv ===\n"
bt 8
finish
finish
finish
printf "=== after three finishes ===\n"
bt 8
printf "cmd address: %p, cmd value: %d\n", &cmd, cmd
x/48bx &cmd
x/6gx &cmd
printf "=== frame layout ===\n"
info frame
p &cmd
kill
quit
