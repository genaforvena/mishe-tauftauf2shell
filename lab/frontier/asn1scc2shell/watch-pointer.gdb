set pagination off
set confirm off
break instrument
run
printf "BREAK: s=%p handler=%p\n", s, (void *)s->handler
set $haddr = &s->handler
watch -l *(void (**)(void))$haddr
continue
printf "WATCH HIT: handler at %p now %p\n", $haddr, *(void (**)(void))$haddr
bt 8
quit
