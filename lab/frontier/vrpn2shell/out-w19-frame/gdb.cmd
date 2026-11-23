set pagination off
set confirm off
set disassembly-flavor intel
break vrpn_Connection.C:4554
commands
silent
printf "HIT i=%d array=%p rsp=%p rbp=%p\n", i, &sender_name, $rsp, $rbp
x/48gx (char*)&sender_name+128
bt 6
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 14400
