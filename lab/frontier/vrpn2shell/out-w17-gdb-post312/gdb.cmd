set pagination off
set confirm off
set disassembly-flavor intel
break vrpn_Connection.C:4554
commands
silent
printf "HIT pc=%p rsp=%p i=%d\n", $pc, $rsp, i
printf "PRE  +136=%p +200=%p +312=%p\n", *(unsigned long*)((char*)$rsp+136), *(unsigned long*)((char*)$rsp+200), *(unsigned long*)((char*)$rsp+312)
tbreak *($pc+6)
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 14241
printf "POST pc=%p rsp=%p\n", $pc, $rsp
printf "POST +136=%p +200=%p +312=%p\n", *(unsigned long*)((char*)$rsp+136), *(unsigned long*)((char*)$rsp+200), *(unsigned long*)((char*)$rsp+312)
x/i $pc
bt 6
continue
