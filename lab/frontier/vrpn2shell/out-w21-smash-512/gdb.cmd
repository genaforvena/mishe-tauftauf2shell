set pagination off
set confirm off
break vrpn_Connection.C:4554
commands
silent
printf "PRE i=%d name=%p dest=%p bt_follows\n", i, sender_name, &sender_name[i]
bt 8
continue
end
break __stack_chk_fail
commands
silent
printf "SMASH rbp=%p rsp=%p\n", $rbp, $rsp
x/4gx $rbp-16
bt 6
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 15150
