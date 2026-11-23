set pagination off
set confirm off
set print elements 0

break author.c:149
commands
 silent
 x/64bx (char *)session->ctx->in + 1156
 printf "ARGCHUNK session=%p m=%p in=%p a12=%p a13=%p a14=%p\n", session, session->mem, session->ctx->in, cmd_argp[12], cmd_argp[13], cmd_argp[14]
 x/32bx cmd_argp[12]
 continue
end

break packet.c:1326
commands
 silent
 printf "CLEANUP session=%p smem=%p\n", session, session->mem
 continue
end

run
printf "INFERIOR_STOPPED\n"
bt 3
quit
