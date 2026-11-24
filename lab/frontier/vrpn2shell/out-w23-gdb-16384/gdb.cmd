set pagination off
set confirm off
break vrpn_Connection.C:4554
commands
silent
printf "PRE i=%d name=%p dest=%p\n", i, sender_name, &sender_name[i]
x/16gx sender_name+16352
continue
end
break vrpn_Connection.C:4556
commands
silent
printf "POST i=%d dest=%p\n", i, &sender_name[i]
x/16gx sender_name+16352
continue
end
break __stack_chk_fail
commands
silent
printf "STACK_CHK_FAIL_HIT\n"
bt 12
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 15041
