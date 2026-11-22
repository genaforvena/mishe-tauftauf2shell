set pagination off
set confirm off
set disable-randomization on
break log_access
run
printf "RBP=%p CANARY_SLOT=%p CANARY_BEFORE=", $rbp, $rbp-8
x/gx $rbp-8
printf "SAVED_RIP_SLOT=%p SAVED_RIP_BEFORE=", $rbp+8
x/gx $rbp+8
break __stack_chk_fail
continue
printf "HIT_STACK_CHK_FAIL\n"
bt 8
printf "CANARY_AT_FAILURE="
x/gx $rbp-8
printf "SAVED_RIP_AT_FAILURE="
x/gx $rbp+8
quit
