set pagination off
set confirm off
break vrpn_Connection.C:4554
commands
silent
printf "PRE i=%d dest=%p canary=%p saved_rbp=%p saved_rip=%p\n", i, &sender_name[i], *(void**)((char*)&sender_name+104), *(void**)((char*)&sender_name+112), *(void**)((char*)&sender_name+120)
continue
end
break vrpn_Connection.C:4556
commands
silent
printf "POST i=%d dest=%p canary=%p saved_rbp=%p saved_rip=%p\n", i, &sender_name[i], *(void**)((char*)&sender_name+104), *(void**)((char*)&sender_name+112), *(void**)((char*)&sender_name+120)
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 13970
