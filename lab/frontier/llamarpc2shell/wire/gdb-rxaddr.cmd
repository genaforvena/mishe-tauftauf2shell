set pagination off
set confirm off
set breakpoint pending on
break transport.cpp:520
run
printf "=== HIT rdma_recv ===\n"
printf "slot=%d src=%p dst=%p got=%zu\n", slot, c->rx_slot(slot), dst, got
x/16bx c->rx_slot(slot)
kill
quit
