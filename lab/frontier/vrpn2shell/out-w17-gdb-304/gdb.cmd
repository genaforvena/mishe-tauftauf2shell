set pagination off
set confirm off
set disassembly-flavor intel
break vrpn_Connection.C:4554
commands
silent
printf "HIT pc=%p rsp=%p i=%d &name=%p\n", $pc, $rsp, i, &sender_name
printf "PRE +200=%p +304=%p +336=%p +392=%p\n", *(void**)((char*)$rsp+200), *(void**)((char*)$rsp+304), *(void**)((char*)$rsp+336), *(void**)((char*)$rsp+392)
set $t304 = (*(unsigned long*)((char*)$rsp+304) & ~0xffUL)
set $t336 = (*(unsigned long*)((char*)$rsp+336) & ~0xffUL)
set $t392 = (*(unsigned long*)((char*)$rsp+392) & ~0xffUL)
printf "TARGETS t304=%p t336=%p t392=%p\n", $t304, $t336, $t392
break *$t304
break *$t336
break *$t392
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 14216
