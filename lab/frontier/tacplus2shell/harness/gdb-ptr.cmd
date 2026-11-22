set pagination off
set confirm off
set print elements 0

break author.c:141
commands
 silent
 printf "EVALARGS in=%p base=%p inlen=%u\n", session->ctx->in, p, session->ctx->in->length
 continue
end

break author.c:75 if i == 12
commands
 silent
 printf "PRE12 i=%d l=%u a=%p t=%p cmdline=%p iaddr=%p tslot=%p\n", (int)i, (unsigned)*argsizep, a, t, cmdline, &i, &t
 continue
end

break author.c:78 if i == 12
commands
 silent
 printf "POST12 t=%p cmdoff=%ld i=%d cmdlineptr=%p\n", t, (long)((char *)t - (char *)cmdline), (int)i, *(void **)((char *)$rbp - 0x68)
 continue
end

break author.c:75 if i == 13
commands
 silent
 printf "PRE13 i=%d l=%u a=%p t=%p tslot=%p cmdline=%p\n", (int)i, (unsigned)*argsizep, a, t, &t, cmdline
 set $tslot = &t
 continue
end

break author.c:78 if i == 13
commands
 silent
 printf "POST13 t=%p tslotval=%p i=%d p=%p argsizep=%p session=%p\n", t, *(void **)$tslot, (int)i, p, argsizep, session
 continue
end

break author.c:75 if i == 14
commands
 silent
 printf "PRE14 i=%d l=%u a=%p t=%p TARGET=%p\n", (int)i, (unsigned)*argsizep, a, t, t
 set $target = t
 printf "PRE14 target_before:\n"
 x/20bx $target
 continue
end

break author.c:78 if i == 14
commands
 silent
 printf "POST14 t=%p TARGET=%p i=%d p=%p argsizep=%p\n", t, $target, (int)i, p, argsizep
 printf "POST14 target_after:\n"
 x/20bx $target
 continue
end

run
printf "INFERIOR STOPPED\n"
bt 8
info registers rip rsp rbp
quit
