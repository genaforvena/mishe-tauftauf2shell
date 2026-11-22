set pagination off
set confirm off
set disable-randomization off
handle SIGABRT stop
run
printf "\n=== abort backtrace ===\n"
bt 24
printf "\n=== casemap frame ===\n"
frame 12
p/x buffer_anchor
x/5gx buffer_anchor
set $first = (mapping_buffer *) *(unsigned long *)(buffer_anchor + 32)
p/x $first
p *$first
set $end = (char *)$first->space + $first->capa
printf "space_end (corrupted size field) = %p\n", $end
x/24gx $end-64
printf "\n=== next chunk header ===\n"
x/16gx $end-24
