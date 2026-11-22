set pagination off
set confirm off
set disable-randomization off
break mapping_buffer_free if ((mapping_buffer *)p)->capa == $wanted
run
frame 0
set $first = (mapping_buffer *)p
p *$first
set $end = (char *)$first->space + $first->capa
set $victim = $end-8
printf "AFTERCAPA end=%p size=%#lx\n", $end, *(unsigned long *)$end
printf "tcache_key=%#lx count30=%u entry30=%p count50=%u entry50=%p\n", tcache_key, tcache->counts[1], tcache->entries[1], tcache->counts[3], tcache->entries[3]
x/64gx $end-64
bt 8
