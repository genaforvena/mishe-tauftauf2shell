# Observe the adjacent qword immediately before and after the real copy.
# The caller sets disable-randomization off and the pinned source directory.
set pagination off
set breakpoint pending on
set confirm off
break main
run
break rpmcpioRead
commands
  silent
  printf "ENTRY_BUF=%p NEXT=%p\n", buf, *(void **)(buf + 0x20)
  continue
end
break rpmfi.cc:2243
commands
  silent
  printf "AT_BUF=%p NEXT=%p\n", buf, *(void **)(buf + 0x20)
  continue
end
continue
