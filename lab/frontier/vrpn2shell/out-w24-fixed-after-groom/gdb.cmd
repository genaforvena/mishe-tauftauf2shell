set pagination off
set confirm off
break vrpn_Connection.C:4557
commands
silent
printf "AFTER_STRNCPY payload_len=%u i_raw=0x%x name=%p\n", p.payload_len, *(unsigned int*)p.buffer, &sender_name
x/48bx &sender_name
bt 3
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 15111
