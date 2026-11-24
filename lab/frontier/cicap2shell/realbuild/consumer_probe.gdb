# W6: observe the plain (non-ASan) second destroy of the aliased entity.
# Usage: gdb -q -batch -x consumer_probe.gdb --args ./real_api_plain attack 90
# Print-only: no memory writes, no forced calls, no source/binary changes.
set pagination off
set confirm off
set print pretty off
set $n = 0
set breakpoint pending on
break destroy_encaps_entity
commands
  silent
  set $n = $n + 1
  printf "W6_DESTROY n=%d e=%p type=%d start=%d entity=%p\n", $n, e, e->type, e->start, e->entity
  continue
end
run
printf "W6_AFTER_RUN\n"
bt 12
quit
