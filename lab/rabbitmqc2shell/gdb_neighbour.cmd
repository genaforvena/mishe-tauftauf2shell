set pagination off
set confirm off
set print address on
break memcpy if $rdx == 200000
run
printf "STOPPED: backtrace follows\n"
bt 5
frame 2
printf "connection state=%p socket object=%p\n", state, state->socket
frame 0
set $ob = $rdi - 7
printf "memcpy dst=%p src=%p len=%ld outbound=%p\n", $rdi, $rsi, $rdx, $ob
printf "BEFORE next-chunk header at outbound+65536 (prev_size, size):\n"
x/2gx $ob+65536
printf "BEFORE next-chunk payload at outbound+65552:\n"
x/8bx $ob+65552
set $np = *(unsigned long *)($ob + 65552)
printf "BEFORE pointer-shaped field at outbound+65552 = %#lx\n", $np
x/8gx $np
finish
printf "AFTER next-chunk header at outbound+65536 (prev_size, size):\n"
x/2gx $ob+65536
printf "AFTER next-chunk payload at outbound+65552:\n"
x/8bx $ob+65552
printf "AFTER chosen-byte offsets:\n"
x/8bx $ob+65536
x/8bx $ob+65544
x/8bx $ob+65584
x/8bx $ob+65600
quit
