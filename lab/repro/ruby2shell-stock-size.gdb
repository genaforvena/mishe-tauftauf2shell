set pagination off
set confirm off
set disable-randomization off
break string.c:7839 if capa == $wanted && *source_current == 97
run
frame 0
set $first = (mapping_buffer *) *(unsigned long *)(buffer_anchor + 32)
set $end = (char *)$first->space + $first->capa
set $victim = $end-8
set $size = *(unsigned long *)$end
set $next = $victim + ($size & ~7)
printf "SIZEPROBE capa=%lu first=%p end=%p size=%#lx next_size=%#lx fd=%p bk=%p\n", $first->capa, $first, $end, $size, *(unsigned long *)($next+8), *(void **)($end+8), *(void **)($end+16)
x/8gx $next
