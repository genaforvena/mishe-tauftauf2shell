set pagination off
set confirm off
break vrpn_Connection.C:405
commands
silent
printf "AT405 this=%p d_entry=%p useEntry=%d remote_id=%d local_id=%d name=%p\n", this, d_entry, useEntry, remote_id, local_id, name
x/2gx &d_entry[useEntry]
continue
end
break vrpn_Connection.C:414
commands
silent
printf "PRE414 useEntry=%d dest=%p name=%p\n", useEntry, d_entry[useEntry].name, name
x/16bx d_entry[useEntry].name
continue
end
break vrpn_Connection.C:415
commands
silent
printf "POST415 useEntry=%d dest=%p\n", useEntry, d_entry[useEntry].name
x/16bx d_entry[useEntry].name
bt 3
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 15352
