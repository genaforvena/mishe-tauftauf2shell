set pagination off
set confirm off
break vrpn_Connection.C:4552
commands
silent
printf "STRNCPY_SITE payload_len=%u buffer=%p name=%p\n", p.payload_len, p.buffer, &sender_name
x/8bx p.buffer
bt 3
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 15110
