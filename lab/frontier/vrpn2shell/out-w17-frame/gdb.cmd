set pagination off
set confirm off
set disassembly-flavor intel
break vrpn_Connection.C:4554
commands
silent
printf "HIT pc=%p rsp=%p rbp=%p rdi=%p rsi=%p rbx=%p i=%d &name=%p\n", $pc, $rsp, $rbp, $rdi, $rsi, $rbx, i, &sender_name
printf "STACK from rsp+128:\n"
x/40gx $rsp+128
printf "CALLERS:\n"
bt 8
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 14200
