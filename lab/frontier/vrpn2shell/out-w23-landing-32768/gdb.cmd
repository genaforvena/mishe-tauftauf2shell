set pagination off
set confirm off
break *0x49db2
commands
silent
printf "STORE pc=%p rbp=%p rax_se=%ld dest=%p\n", $pc, $rbp, $rax, $rbp-0x70+$rax
x/i $pc
stepi
printf "AFTER_STORE pc=%p\n", $pc
printf "SI_ADDR %p\n", $_siginfo._sifields._sigfault.si_addr
bt 6
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 15052
