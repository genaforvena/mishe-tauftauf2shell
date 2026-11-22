set pagination off
set confirm off
set disassembly-flavor intel
break vrpn_Connection.C:4554
commands
silent
printf "PRE i=%d &name=%p rbp=%p rsp=%p rip136=%p\n", i, &sender_name, $rbp, $rsp, *(void**)((char*)&sender_name+136)
x/4i $pc
continue
end
break vrpn_Connection.C:4556
commands
silent
printf "POST i=%d &name=%p rip136=%p\n", i, &sender_name, *(void**)((char*)&sender_name+136)
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 14104
