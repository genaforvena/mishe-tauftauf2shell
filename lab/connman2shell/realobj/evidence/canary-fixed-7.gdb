set pagination off
set confirm off
break main
run --help
set $buf = (char *) malloc(2048)
call (void*) memset($buf, 255, 2048)
set $buf[1024] = 7
printf "CANARY_LOW=%02x\n", *(unsigned char*)($fs_base + 0x28)
call (void*) get_domains(2048, $buf)
printf "CALL_RETURNED\n"
quit
