set pagination off
set confirm off
break websock.c:216 if i == 0
run
printf "P=%p MB_BUF=%p MB_SIZE=%lu\n", p, mb->buf, (unsigned long)mb->size
printf "MEM_HEADER_SIZE=%lu\n", (unsigned long)mem_header_size
set $mem = (char *)mb->buf - mem_header_size
printf "MALLOC_PTR=%p GLIBC_SIZE_WORD=%lu USABLE=%lu\n", $mem, *(unsigned long *)($mem-8), (unsigned long)malloc_usable_size($mem)
printf "NEXT_CHUNK_AT=%p OFF_FROM_P=%lu\n", $mem-16+*(unsigned long *)($mem-8), (unsigned long)($mem-16+*(unsigned long *)($mem-8)-p)
x/8gx $mem-16
quit
