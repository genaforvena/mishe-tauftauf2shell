set pagination off
set confirm off
set print elements 0

break author.c:141
commands
 silent
 printf "EVAL in=%p session=%p smem=%p smemfield=%p\n", session->ctx->in, session, session->mem, &session->mem
 continue
end

break author.c:78 if i == 14
commands
 silent
 printf "POST14 t=%p TARGET=%p\n", t, t
 continue
end

break mem_destroy
commands
 silent
 printf "DESTROY m=%p type=%u count=%u arr=%p\n", m, *(unsigned *)((char *)m + 8), *(unsigned *)((char *)m + 12), *(void **)((char *)m + 16)
 if *(unsigned *)((char *)m + 12) > 0
  printf "ARR0 f=%p p=%p\n", *(void **)(*(void **)((char *)m + 16)), *((void **)(*(void **)((char *)m + 16)) + 1)
  x/s *((void **)(*(void **)((char *)m + 16)) + 1)
 end
 continue
end

run
printf "INFERIOR_STOPPED\n"
bt 5
quit
