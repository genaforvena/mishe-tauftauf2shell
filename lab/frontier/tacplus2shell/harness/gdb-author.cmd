set pagination off
set confirm off
set print elements 0
set $base = (char*)0
set $cmdb = (char*)0
break author.c:122
commands
 silent
 printf "A122 p=%p user=%p txt=%s in=%p inlen=%u\n", p, session->username.txt, session->username.txt, session->ctx->in, session->ctx->in->length
 continue
end
break author.c:72
commands
 silent
 set $base = p
 set $cmdb = cmdline
 printf "ENTER base=%p cmdline=%p argcnt=%zu inlen=%u\n", $base, $cmdb, argcnt, session->ctx->in->length
 x/192bx $base
 continue
end
break author.c:75 if a - $base >= 64
commands
 silent
 printf "L75OOB i=%zu a=%p off=%ld l=%zu\n", i, a, (long)(a-$base), l
 x/8bx a
 continue
end
break author.c:77
commands
 silent
 printf "L77 i=%zu a=%p off=%ld l=%zu len=%zu\n", i, a, (long)(a-$base), l, len
 x/12bx a
 continue
end
break author.c:78
commands
 silent
 printf "L78 i=%zu tlen=%zu cmdoff=%ld\n", i, tlen, (long)(t-$cmdb)
 x/s $cmdb
 continue
end
run
printf "INFERIOR STOPPED\n"
bt 8
quit
