set pagination off
set confirm off
set breakpoint pending on
break socket_t::impl::rdma_recv
run
printf "=== HIT rdma_recv ===\n"
finish
finish
finish
printf "=== after three finishes: saved-RIP probe ===\n"
bt 4
printf "cmd address: %p\n", &cmd
printf "saved RIP slot at &cmd+3585:\n"
x/8bx &cmd+3585
x/gx &cmd+3585
printf "first 48 bytes of cmd sink:\n"
x/48bx &cmd
kill
quit
