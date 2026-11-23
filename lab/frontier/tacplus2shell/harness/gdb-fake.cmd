set pagination off
set confirm off
set print elements 0

break author.c:141
commands
 silent
 printf "SLOT session=%p smem_field=%p smem_val=%p in=%p\n", session, &session->mem, session->mem, session->ctx->in
 continue
end

break packet.c:1326
commands
 silent
 printf "CLEANUP session=%p smem_field=%p smem_val=%p\n", session, &session->mem, session->mem
 continue
end

run
printf "INFERIOR_STOPPED\n"
bt 3
quit
