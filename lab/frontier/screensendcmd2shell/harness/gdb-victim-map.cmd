set pagination off
set confirm off
break attacher.c:435
run -X echo hi
printf "SOCKETPATH_LEN=%lu\n", (unsigned long)strlen(SocketPath)
printf "ATTACK_STY_LEN=%lu\n", (unsigned long)strlen(sty)
printf "VICTIM_BASE=%p IDX0=%p IDX64=%p IDX200=%p IDX239=%p\n", &attach_tty_name_in_ns[0], &attach_tty_name_in_ns[0], &attach_tty_name_in_ns[64], &attach_tty_name_in_ns[200], &attach_tty_name_in_ns[239]
printf "BYTES 0,16,32,48,64,100,200,239,240: %#x %#x %#x %#x %#x %#x %#x %#x %#x\n", attach_tty_name_in_ns[0], attach_tty_name_in_ns[16], attach_tty_name_in_ns[32], attach_tty_name_in_ns[48], attach_tty_name_in_ns[64], attach_tty_name_in_ns[100], attach_tty_name_in_ns[200], attach_tty_name_in_ns[239], attach_tty_name_in_ns[240]
quit
