set pagination off
set confirm off
break vrpn_Connection.C:4554
commands
silent
printf "WRITE_SITE_HIT i=%d &sender_name=%p dest=%p payload_len=%u\n", i, &sender_name, &sender_name[i], p.payload_len
x/4bx p.buffer
bt 3
p/x &sender_name
p/x &p
p p.buffer
p p.payload_len
p/x &endpoint
p endpoint
x/40gx &sender_name-128
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 13911
