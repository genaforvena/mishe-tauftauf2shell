set pagination off
set confirm off
break vrpn_Connection.C:414
commands
silent
if useEntry == -2
printf "PRE414 slot=%p name=%p remote_id=%d local_id=%d slotdata=%p plus8=%p\n", &d_entry[useEntry], d_entry[useEntry].name, d_entry[useEntry].remote_id, d_entry[useEntry].local_id, *(void**)&d_entry[useEntry], *(void**)((char*)&d_entry[useEntry]+8)
x/16bx d_entry[useEntry].name
end
continue
end
break vrpn_Connection.C:427
commands
silent
if useEntry == -2
printf "POST427 slot=%p slotdata=%p plus8=%p remote_id=%d local_id=%d\n", &d_entry[useEntry], *(void**)&d_entry[useEntry], *(void**)((char*)&d_entry[useEntry]+8), d_entry[useEntry].remote_id, d_entry[useEntry].local_id
x/16bx *(char**)((char*)&d_entry[useEntry])
bt 3
end
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 15369
