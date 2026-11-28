set pagination off
set confirm off
set breakpoint pending on
break __stack_chk_fail
commands 1
  silent
  printf "R4L-FAIL backtrace:\n"
  bt 5
  frame function _session_ticket
  printf "R4L frame rbp=%p dst=%p canary=%p savedrip=%p\n", $rbp, &opaque_plaintext, $rbp-0x18, $rbp+8
  printf "R4L fs_canary="
  x/gx $fs_base+0x28
  printf "R4L canary_slot="
  x/gx $rbp-0x18
  printf "R4L saved_rbp_slot="
  x/gx $rbp
  printf "R4L saved_rip_and_next3:\n"
  x/4gx $rbp+8
  printf "R4L dst+144..207:\n"
  x/26bx $rbp-0xb0+144
  continue
end
run -X -d ./install/etc/raddb -i 127.0.0.1 -p 18120
