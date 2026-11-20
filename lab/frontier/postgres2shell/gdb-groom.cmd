# gdb -q -batch -p <backend-pid> -x gdb-groom.cmd
# Exact-build debug symbols required: postgresql-17-dbgsym=17.11-1.pgdg13+2
# Break after rslots[i] is loaded (nodeModifyTable.c:1268). Dump 40 pointers
# at i=0 so the tail past ri_Slots (incl. the adjacent ri_PlanSlots array)
# is captured, then log every consumed slot pointer.
set pagination off
set confirm off
set print pretty off
break *ExecBatchInsert+120
commands
 silent
 printf "HIT i=%d numInserted=%d rslots=%p slot=%p\n", $r12d, $edx, $r14, $rbx
 if $r12d == 0
   x/40gx $r14
 end
 continue
end
continue
printf "STOPPED rip=%p\n", $rip
bt 8
detach
quit
