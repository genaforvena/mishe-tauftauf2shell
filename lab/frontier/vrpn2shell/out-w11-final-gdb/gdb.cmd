set pagination off
set confirm off
set disassembly-flavor intel
break *0x40be40
commands
silent
printf "STUB_HIT rsp=%p ret_at_rsp=%p\n", $rsp, *(void**)$rsp
bt 4
continue
end
break *0x413dda
commands
silent
printf "RESUME_413DDA rsp=%p\n", $rsp
bt 3
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 14118
