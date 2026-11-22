set pagination off
set confirm off
set disable-randomization on
break logconf.c:843
run
set $le = line_end
printf "AT_843 LINE=%p LINE_END=%p CAP=%ld ERROR_SIZE=%lu\n", line, line_end, (long)(line_end-line), (unsigned long)req->error_logs->size
finish
printf "AFTER_RETURN LEN=%lu\n", (unsigned long)len
x/32gx $le
x/16bx $le
bt 3
quit
