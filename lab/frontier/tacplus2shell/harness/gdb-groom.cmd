set pagination off
set confirm off
set print elements 0
set $prime_in = (char*)0
set $prime_base = (char*)0
# Capture the large prime packet's buffer and arg base.
break authen.c:2171
commands
 silent
 set $prime_in = session->ctx->in
 printf "AUTHEN payload first bytes:\n"
 x/32bx session->ctx->in + 40
 printf "AUTHEN in=%p len=%u\n", $prime_in, session->ctx->in->length
 continue
end
break author.c:122
commands
 silent
 if session->ctx->in->length > 100
  set $prime_in = session->ctx->in
  set $prime_base = p
  printf "PRIME in=%p base=%p inlen=%u\n", $prime_in, $prime_base, session->ctx->in->length
 end
 continue
end
# Only the small trigger packet.
break author.c:72 if session->ctx->in->length < 200
commands
 silent
 printf "TRIG in=%p base=%p inlen=%u prime_in=%p prime_base=%p\n", session->ctx->in, p, session->ctx->in->length, $prime_in, $prime_base
 printf "TRIG dump 256 bytes at base:\n"
 x/256bx p
 printf "SEARCH first ZZZZ from prime_in over 32KB:\n"
 find /b $prime_in, $prime_in+32768, 0x5a, 0x5a, 0x5a, 0x5a
 printf "SEARCH ZZZZ from trig base over 4KB:\n"
 find /b p, p+4096, 0x5a, 0x5a, 0x5a, 0x5a
 continue
end
break author.c:78
commands
 silent
 printf "L78 i=%zu tlen=%zu cmdoff=%ld\n", i, tlen, (long)(t-cmdline)
 x/s cmdline
 continue
end
run
printf "INFERIOR STOPPED\n"
bt 4
quit
