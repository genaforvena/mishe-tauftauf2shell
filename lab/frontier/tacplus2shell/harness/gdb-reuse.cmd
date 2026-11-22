set pagination off
set confirm off
set print elements 0
set $prime_in = (char*)0
set $prime_len = 0
# Large seq>=2 AUTHEN/CONT prime: buffer is ctx-owned, freed at packet.c:917.
set $nclean = 0
break send_authen_reply
commands
 silent
 printf "AUTHEN_REPLY status=%d seq=%d\n", status, session->seq_no
 continue
end
break cleanup_session
commands
 silent
 set $nclean = $nclean + 1
 printf "CLEANUP #%d session=%p\n", $nclean, session
 continue
end
break packet.c:775
commands
 silent
 printf "STRAY seq=%d\n", ctx->hdr.tac.seq_no
 continue
end
break packet.c:763
commands
 silent
 printf "SEQBAD got=%d want=%d\n", ctx->hdr.tac.seq_no, session->seq_no
 continue
end
break packet.c:878 if ctx->hdr.tac.type == 1 && ctx->in->length > 1000
commands
 silent
 set $prime_in = (char*)ctx->in
 set $prime_len = ctx->in->length
 printf "PRIME in=%p len=%u\n", $prime_in, $prime_len
 printf "PRIME at body+108:\n"
 x/32bx ((char*)ctx->in)+152
 continue
end
# Small AUTHOR trigger.
break author.c:72 if session->ctx->in->length < 200
commands
 silent
 printf "TRIG in=%p base=%p inlen=%u prime_in=%p prime_len=%u\n", session->ctx->in, p, session->ctx->in->length, $prime_in, $prime_len
 printf "TRIG post-payload 96 bytes:\n"
 x/96bx p+64
 printf "TRIG far 64 bytes at p+1020:\n"
 x/64bx p+1020
 printf "FIND ZZZZ from p over 2KB:\n"
 find /b p, p+2048, 0x5a, 0x5a, 0x5a, 0x5a
 continue
end
break author.c:78
commands
 silent
 printf "L78 i=%zu tlen=%zu cmdoff=%ld\n", i, tlen, (long)(t-cmdline)
 x/s cmdline
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
bt 4
quit
