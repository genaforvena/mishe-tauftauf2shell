set pagination off
set confirm off
set disassembly-flavor intel
break vrpn_Connection.C:4554
commands
silent
printf "HIT-REGS pc=%p rbp=%p rsp=%p rdi=%p rsi=%p rdx=%p rcx=%p rax=%p rbx=%p\n", $pc, $rbp, $rsp, $rdi, $rsi, $rdx, $rcx, $rax, $rbx
x/12i $pc-24
info registers rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11
printf "HIT-VAR i=%d &sender_name=%p\n", i, &sender_name
printf "HIT-WORDS +104=%p +112=%p +120=%p +128=%p +136=%p\n", *(void**)((char*)&sender_name+104), *(void**)((char*)&sender_name+112), *(void**)((char*)&sender_name+120), *(void**)((char*)&sender_name+128), *(void**)((char*)&sender_name+136)
bt 5
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 14012
