set pagination off
set confirm off
set print pretty on
break logconf.c:843
run
printf "HIT843\n"
info args
printf "LINE=%p POS=%p POSOFF=%ld ERROR_SIZE=%lu\n", line, pos, (long)(pos - line), (unsigned long)req->error_logs->size
x/16bx pos-4
finish
printf "RETURNED_TO_LOG_ACCESS\n"
x/64bx buf+4064
bt 3
quit
