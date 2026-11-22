set pagination off
set confirm off
break vrpn_Connection.C:4554
commands
silent
printf "LAYOUT &p=%p &p.buffer=%p &p.payload_len=%p &endpoint=%p &sender_name=%p\n", &p, &p.buffer, &p.payload_len, &endpoint, &sender_name
printf "PRE i=%d dest=%p p.buffer=%p p.payload_len=%d endpoint=%p saved_rip=%p\n", i, &sender_name[i], p.buffer, p.payload_len, endpoint, *(void**)((char*)&sender_name+120)
x/8gx &sender_name[i]-32
x/1bx &sender_name[i]
continue
end
break vrpn_Connection.C:4556
commands
silent
printf "POST i=%d dest=%p p.buffer=%p p.payload_len=%d endpoint=%p saved_rip=%p\n", i, &sender_name[i], p.buffer, p.payload_len, endpoint, *(void**)((char*)&sender_name+120)
x/8gx &sender_name[i]-32
x/1bx &sender_name[i]
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 13915
