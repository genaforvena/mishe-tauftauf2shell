set pagination off
set confirm off
set breakpoint pending on
break __GI___libc_free
commands
  silent
  if $rdi != 0
    printf "FREEARG ptr=%p\n", $rdi
    x/4gx $rdi-16
  end
  continue
end
run
printf "STOP\n"
bt 8
