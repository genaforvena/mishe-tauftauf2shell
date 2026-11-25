set pagination off
set print pretty on
set confirm off
break ccx_gxf.c:1220
run lab/frontier/ccextractor2shell/real-build/inputs/attack.gxf -o /tmp/ccx2shell-readback-page.scc
printf "STOP_READ data_len=%lu buffer=%p\n", data->len, data->buffer
set $rb = (unsigned char *)data->buffer + 2097272
set $pg = (void *)((unsigned long)$rb & ~0xfffUL)
printf "GUARD_PAGE=%p TARGET=%p\n", $pg, $rb
call (int)mprotect($pg, 4096, 0)
continue
printf "STOP_AFTER_GUARD rip=%p\n", $pc
bt 12
x/16xb $rb
quit
