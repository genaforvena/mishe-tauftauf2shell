# gdb -q -batch -p <backend-pid> -x gdb.cmd
# Exact-build debug symbols required: postgresql-17-dbgsym=17.11-1.pgdg13+2
# Break at ExecBatchInsert+120: after rslots[i] is loaded into %rbx, per
# nodeModifyTable.c:1268-1274 of REL_17_11.
set pagination off
set confirm off
set print pretty off
break *ExecBatchInsert+120
commands
 silent
 printf "HIT i=%d numInserted=%d rslots=%p slot=%p\n", $r12d, $edx, $r14, $rbx
 if $r12d == 0
   x/16gx $r14
 end
 continue
end
continue
printf "STOPPED rip=%p\n", $rip
bt 10
detach
quit
