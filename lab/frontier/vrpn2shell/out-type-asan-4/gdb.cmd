set pagination off
set confirm off
break vrpn_Connection.C:4482
commands
silent
printf "WRITE_SITE_HIT i=%d &type_name=%p dest=%p payload_len=%u\n", i, &type_name, &type_name[i], p.payload_len
x/4bx p.buffer
bt 3

continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 13912
