set pagination off
set confirm off
set print elements 0

break author.c:141
commands
 silent
 printf "SLOT session=%p smem_field=%p smem_val=%p in=%p\n", session, &session->mem, session->mem, session->ctx->in
 continue
end

break author.c:78 if i == 14
commands
 silent
 printf "POST14 t=%p smem_field=%p smem_val=%p i=%d\n", t, &session->mem, session->mem, (int)i
 x/16bx &session->mem
 continue
end

break packet.c:1326
commands
 silent
 printf "CLEANUP session=%p smem_field=%p smem_val=%p\n", session, &session->mem, session->mem
 x/160bx (char *)session->ctx->in + 1156
 continue
end

break mem_destroy
commands
 silent
 printf "DESTROY m=%p type=%u count=%u arr=%p rdi=%p rip=%p\n", m, *(unsigned *)((char *)m + 8), *(unsigned *)((char *)m + 12), *(void **)((char *)m + 16), $rdi, $rip
 if *(void **)((char *)m + 16) != 0
  x/32bx m
  x/32bx *(void **)((char *)m + 16)
 end
 continue
end

run
printf "INFERIOR_STOPPED\n"
bt 4
quit
