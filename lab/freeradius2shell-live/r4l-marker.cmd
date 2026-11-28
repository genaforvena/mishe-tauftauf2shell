set pagination off
set confirm off
set breakpoint pending on
break main
commands 1
  silent
  printf "R4L-CANARY %lx\n", *(unsigned long long *)($fs_base+0x28)
  printf "R4L-MARKER %p\n", benign_marker
  continue
end
break __stack_chk_fail
commands 2
  silent
  printf "R4L-CANARY-FAIL reached (unexpected)\n"
  frame function _session_ticket
  printf "R4L-Unexpected canary slot="
  x/gx $rbp-0x18
  continue
end
run -X -d ./install/etc/raddb -i 127.0.0.1 -p 18120
