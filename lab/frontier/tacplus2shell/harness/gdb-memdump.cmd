set pagination off
set confirm off
set print elements 0

break author.c:141
commands
 silent
 set $m = (char *)session->mem
 printf "MEMDUMP m=%p type=%u count=%u arr=%p list=%p\n", $m, *(unsigned *)($m + 8), *(unsigned *)($m + 12), *(void **)($m + 16), *(void **)$m
 x/96bx $m
 printf "MEMDUMP in=%p\n", session->ctx->in
 continue
end
run
quit
