set pagination off
set confirm off
set breakpoint pending on
source lab/frontier/ccextractor2shell/real-build/gdb-w10-udp.py
break ccx_gxf.c:1220
run
python scan()
set $buf = (unsigned long)data->buffer
python MB()
break free if $rdi == $buf
continue
printf "W10PY FREE top=%p nextsize=0x%lx\n", main_arena.top, *(unsigned long*)($buf+2097272)
quit
