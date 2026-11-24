set pagination off
set confirm off
break vrpn_Connection.C:405
commands
silent
if useEntry == 4
printf "PRE405 slot=%p slotdata=%p plus8=%p plus12=%d this=%p\n", &d_entry[useEntry], *(void**)&d_entry[useEntry], *(void**)((char*)&d_entry[useEntry]+8), d_entry[useEntry].local_id, this
end
continue
end
break vrpn_Connection.C:427
commands
silent
if useEntry == 4
printf "POST427 slot=%p slotdata=%p plus8=%p tcpinbuf=%p remote_id=%d local_id=%d\n", &d_entry[useEntry], *(void**)&d_entry[useEntry], *(void**)((char*)&d_entry[useEntry]+8), *(void**)((char*)this-32), d_entry[useEntry].remote_id, d_entry[useEntry].local_id
end
continue
end
break vrpn_Connection.C:4228
commands
silent
printf "GETBODY buf=%p ceil_len=%d fd=%d\n", buf, (int)ceil_len, fd
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 15373
