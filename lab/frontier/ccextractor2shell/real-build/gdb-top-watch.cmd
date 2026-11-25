set pagination off
set confirm off
set breakpoint pending on
break ccx_gxf.c:1220
run
set $target = (unsigned long)data->buffer
set $p = $target + 2097264
set $t = $target + 2097520
printf "W4TOP buffer=0x%lx P=0x%lx top_before=0x%lx\n", $target, $p, main_arena.top
break free if $rdi == $target
watch -l main_arena.top
watch -l *(unsigned long*)$p
watch -l *(unsigned long*)$t
continue
printf "W4TOP STOP1 reason=%s\n", $pc
printf "W4TOP top_now=0x%lx P_prev_size=0x%lx T=0x%lx\n", main_arena.top, *(unsigned long*)$p, *(unsigned long*)$t
bt 5
continue
printf "W4TOP STOP2\n"
printf "W4TOP top_now=0x%lx P_prev_size=0x%lx T=0x%lx\n", main_arena.top, *(unsigned long*)$p, *(unsigned long*)$t
bt 5
quit
