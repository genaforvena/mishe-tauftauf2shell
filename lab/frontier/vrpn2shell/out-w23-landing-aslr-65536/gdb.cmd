set pagination off
set confirm off
set disable-randomization off
break vrpn_Connection.C:4554
commands
silent
printf "STORE i=%d rbp=%p name=%p dest=%p\n", i, $rbp, sender_name, &sender_name[i]
x/i $pc
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 15058
printf "STOP pc=%p si_addr=%p\n", $pc, $_siginfo._sifields._sigfault.si_addr
x/i $pc
bt 6
