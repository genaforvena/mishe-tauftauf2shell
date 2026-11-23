set pagination off
set confirm off
set breakpoint pending on
set disable-randomization off
break system
run
printf "=== HIT system ===\n"
printf "command pointer: %p\n", $rdi
printf "command string: %s\n", $rdi
bt 6
continue
printf "=== CONTINUED ===\n"
kill
quit
