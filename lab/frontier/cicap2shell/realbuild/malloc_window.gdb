# W6: detect any malloc between the first and second destroy of the alias.
# Usage: gdb -q -batch -x malloc_window.gdb --args ./real_api_plain attack 90
# Breakpoint 2 (malloc) is enabled only between destroy calls 6 and 7.
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
  if $n == 6
    enable 2
  end
  if $n == 7
    disable 2
  end
  continue
end
break malloc
commands
  silent
  printf "W6_MALLOC_IN_WINDOW n=%d\n", $n
  continue
end
disable 2
run
printf "W6_AFTER_RUN\n"
bt 6
quit
