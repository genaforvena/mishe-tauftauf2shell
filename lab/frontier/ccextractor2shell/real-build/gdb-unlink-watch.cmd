set pagination off
set confirm off
set breakpoint pending on
break ccx_gxf.c:1220
run
set $target = (unsigned long)data->buffer
set $p = $target + 2097264
set $t = $target + 2097520
printf "W4 buffer=0x%lx P=0x%lx T=0x%lx\n", $target, $p, $t
x/6gx $p
printf "W4 old_T=0x%lx\n", *(unsigned long*)$t
break free if $rdi == $target
watch -l *(unsigned long*)$t
handle SIGABRT stop print nopass
continue
printf "W4 STOP1 pc=%s\n", $pc
bt 8
printf "W4 T_after_stop1=0x%lx\n", *(unsigned long*)$t
continue
printf "W4 STOP2 pc=%s\n", $pc
bt 8
printf "W4 T_after_stop2=0x%lx\n", *(unsigned long*)$t
quit
