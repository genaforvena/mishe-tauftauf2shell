# gdb -q -batch -p <backend-pid> -x gdb-marker.cmd
# Chunk-placement probe 2026-11-21. Break at the OOB loop head
# (nodeModifyTable.c:1268/1274) and dump rslots[] plus the arena words that
# follow it, so we can see whether any OOB word is a SQL-placed value.
set pagination off
set confirm off
set print pretty off
break *ExecBatchInsert+120
commands
 silent
 printf "HIT i=%d numInserted=%d rslots=%p slot=%p\n", $r12d, $edx, $r14, $rbx
 if $r12d == 0
   printf "numSlots=%d\n", numSlots
   printf "ri_Slots=%p ri_PlanSlots=%p ri_BatchSize=%d\n", resultRelInfo->ri_Slots, resultRelInfo->ri_PlanSlots, resultRelInfo->ri_BatchSize
   printf "slots=%p planSlots=%p\n", slots, planSlots
   printf "=== 48 words from rslots (OOB tail included) ===\n"
   x/48gx $r14
   printf "=== 16 words from planSlots ===\n"
   x/16gx planSlots
   printf "=== relation OID to be stored ===\n"
   p/x resultRelInfo->ri_RelationDesc->rd_id
 end
 continue
end
continue
printf "STOPPED rip=%p slot=%p\n", $rip, $rbx
bt 8
detach
quit
