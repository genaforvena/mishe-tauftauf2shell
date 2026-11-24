set pagination off
set breakpoint pending on
break jl2005c_init
run usb:001,001
set $r1=$rbp
set $r2=*(unsigned long*)$r1
call m2s_hexenv("M2SHELL_JL2005_RBP", $r2)
call m2s_hexenv("M2SHELL_JL2005_RIP", *(unsigned long*)($r1+8))
call m2s_hexenv("M2SHELL_VUSB_CALLER_RBX", *(unsigned long*)($r2-8))
call m2s_hexenv("M2SHELL_VUSB_CALLER_RBP", *(unsigned long*)$r2)
call m2s_hexenv("M2SHELL_VUSB_CALLER_RIP", *(unsigned long*)($r2+8))
continue
