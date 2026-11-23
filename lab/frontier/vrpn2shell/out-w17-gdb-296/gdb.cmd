set pagination off
set confirm off
set disassembly-flavor intel
break vrpn_Connection.C:4554
commands
silent
printf "HIT pc=%p rsp=%p i=%d &name=%p\n", $pc, $rsp, i, &sender_name
printf "EXPR +136=%p +200=%p +296=%p +328=%p +392=%p\n", *(void**)((char*)$rsp+136), *(void**)((char*)$rsp+200), *(void**)((char*)$rsp+296), *(void**)((char*)$rsp+328), *(void**)((char*)$rsp+392)
printf "RAW x/gx at +296:\n"
x/gx $rsp+296
printf "RAW stack +128..+400:\n"
x/34gx $rsp+128
bt 8
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 14211
