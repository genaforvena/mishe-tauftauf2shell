set pagination off
set confirm off
break icalcomponent.c:197
commands
  silent
  printf "OBSERVED_FREE c=%p parent=%p\n", c, c->parent
  continue
end
run chosen
