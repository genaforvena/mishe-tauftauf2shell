set pagination off
set confirm off
set breakpoint pending on
break ccx_gxf.c:1220
run
set $buf = (unsigned long)data->buffer
set $p = $buf + 2097264
printf "W6LATE buf=0x%lx P=0x%lx top=0x%lx\n", $buf, $p, main_arena.top
set $n = 0
break __libc_malloc if $n < 24
commands
 silent
 set $n = $n + 1
 printf "W6LATE malloc#%d size=%lu top=0x%lx\n", $n, $rdi, main_arena.top
 bt 3
 continue
end
break free if $rdi == $buf
continue
printf "W6LATE FREE top=0x%lx Psize=0x%lx mallocs=%d\n", main_arena.top, *(unsigned long*)($p+8), $n
quit
