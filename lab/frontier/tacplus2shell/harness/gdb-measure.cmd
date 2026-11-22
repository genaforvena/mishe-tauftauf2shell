set pagination off
set confirm off
set print elements 0

break author.c:141
commands
 silent
 printf "MEASURE session=%p mem=%p arr=%p count=%u\n", session, session->mem, *(void **)((char *)session->mem + 16), *(unsigned *)((char *)session->mem + 12)
 printf "MEASURE system=%p in=%p\n", system, session->ctx->in
 continue
end
run
quit
