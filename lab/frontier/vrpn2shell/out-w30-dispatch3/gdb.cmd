set pagination off
set confirm off
break vrpn_Connection.C:405
commands
silent
if useEntry == -3
printf "PRE405 slot=%p slotdata=%p plus8=%p plus12=%d this=%p\n", &d_entry[useEntry], *(void**)&d_entry[useEntry], *(void**)((char*)&d_entry[useEntry]+8), d_entry[useEntry].local_id, this
end
continue
end
break vrpn_Connection.C:4562
commands
silent
printf "DISPATCH sender_name=%s local_id=%d numSenders=%d\n", sender_name, local_id, endpoint->d_dispatcher->d_numSenders
set $w30i = 0
while $w30i < endpoint->d_dispatcher->d_numSenders
printf "SENDERID[%d]=%s\n", $w30i, endpoint->d_dispatcher->d_senders[$w30i]
set $w30i = $w30i + 1
end
continue
end
break vrpn_Connection.C:427
commands
silent
if useEntry == -3
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
run -f lab/frontier/vrpn2shell/vrpn.cfg 15376
