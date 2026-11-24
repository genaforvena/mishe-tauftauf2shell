set pagination off
set breakpoint pending on
break jl2005c_init
run
set $r1 = $rbp
set $r2 = *(void **)$r1
printf "GDB_R1=%p\n", $r1
printf "GDB_AT_R1=%p\n", *(void **)$r1
printf "GDB_AT_R1_8=%p\n", *(void **)($r1 + 8)
printf "GDB_R2=%p\n", $r2
printf "GDB_R2_MINUS8=%p\n", *(void **)($r2 - 8)
printf "GDB_AT_R2=%p\n", *(void **)$r2
printf "GDB_AT_R2_8=%p\n", *(void **)($r2 + 8)
continue
