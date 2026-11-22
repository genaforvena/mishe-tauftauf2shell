set pagination off
set confirm off
set disable-randomization off
break string.c:7834 if capa == $wanted
run
frame 0
printf "\n=== second casemap allocation ===\n"
p/x buffer_anchor
set $first = (mapping_buffer *) *(unsigned long *)(buffer_anchor + 32)
p *$first
set $end = (char *)$first->space + $first->capa
set $victim = $end-8
printf "space_end=%p victim=%p\n", $end, $victim
x/16gx $end-64
set $next = $victim + (*(unsigned long *)$end & ~7)
printf "computed next chunk = %p\n", $next
x/12gx $next
bt 8
