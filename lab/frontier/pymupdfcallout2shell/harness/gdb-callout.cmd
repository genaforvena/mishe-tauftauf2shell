set pagination off
set breakpoint pending on
break _wrap_JM_set_annot_callout_line
run
set $frame = $rsp
set $before_pops = $pc + 236
printf "FRAME=%p ENTRY_RET=%p\n", $frame, *(void**)$frame
break *$before_pops
continue
printf "AT_POPS pc=%p rsp=%p rbp=%p\n", $pc, $rsp, $rbp
x/4gx $frame-16
x/gx $frame
continue
