set pagination off
set confirm off
set disable-randomization on
break logconf.c:843 if req->error_logs != 0 && req->error_logs->size > 6000
run
set $le = line_end
set $nx = line + 8192
printf "HIT LINE=%p LINE_END=%p CAP=%ld ERROR_SIZE=%lu NEXT=%p\n", line, line_end, (long)(line_end-line), (unsigned long)req->error_logs->size, $nx
printf "CHUNK_BEFORE prev_size=%lu size=%lu\n", *(unsigned long*)(line-16), *(unsigned long*)(line-8)
printf "CHUNK_AFTER prev_size=%lu size=%lu\n", *(unsigned long*)$nx, *(unsigned long*)($nx+8)
x/8gx $nx
info proc mappings
finish
printf "AFTER_RETURN LEN=%lu\n", (unsigned long)len
x/8gx $le
bt 3
quit
