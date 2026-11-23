set pagination off
set confirm off
break vrpn_Connection.C:4554
commands
silent
set $slot176 = (char*)&sender_name+176
set $slot328 = (char*)&sender_name+328
printf "PRE i=%d array=%p\n", i, &sender_name
printf "PRE slot176=%p slot328=%p\n", *(void**)$slot176, *(void**)$slot328
continue
end
break vrpn_Connection.C:1447
commands
silent
printf "POST-RETURN line1447 slot176=%p slot328=%p\n", *(void**)$slot176, *(void**)$slot328
bt 4
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 14430
