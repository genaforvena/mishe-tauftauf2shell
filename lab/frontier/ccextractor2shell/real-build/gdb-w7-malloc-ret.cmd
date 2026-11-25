set pagination off
set confirm off
set breakpoint pending on
source lab/frontier/ccextractor2shell/real-build/gdb-w7-malloc-ret.py
break ccx_gxf.c:1220
run
set $buf = (unsigned long)data->buffer
printf "W7PY buf=%p top=%p topsize_field=0x%lx\n", data->buffer, main_arena.top, *(unsigned long*)($buf+2097272)
python MB()
break free if $rdi == $buf
continue
printf "W7PY FREE top=%p topsize_field=0x%lx\n", main_arena.top, *(unsigned long*)($buf+2097272)
quit
