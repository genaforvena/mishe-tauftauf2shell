set pagination off
set confirm off
set disassembly-flavor intel
break vrpn_Connection.C:4482
commands
silent
printf "PRE pc=%p rsp=%p rbp=%p rbx=%p i=%d dest=%p byte=0x%x\n", $pc, $rsp, $rbp, $rbx, i, (char*)&type_name+i, *(unsigned char*)((char*)&type_name+i)
printf "PRE-REDZONE from rsp-128:\n"
x/20gx $rsp-128
printf "PRE-FRAME from rsp+128:\n"
x/8gx $rsp+128
bt 5
continue
end
break vrpn_Connection.C:4488
commands
silent
printf "POST pc=%p byte=0x%x\n", $pc, *(unsigned char*)((char*)&type_name+(-8))
printf "POST-REDZONE from rsp-128:\n"
x/20gx $rsp-128
printf "POST-FRAME from rsp+128:\n"
x/8gx $rsp+128
bt 3
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 14325
