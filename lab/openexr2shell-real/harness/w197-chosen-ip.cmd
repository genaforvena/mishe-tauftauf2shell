# W197: prove the indirect call target in exr_attr_opaquedata_destroy() is
# the file-chosen address, and that the CPU actually reaches it.  ASLR OFF
# in the debuggee so the file-carried absolute addresses are meaningful.
set pagination off
set confirm off
set disable-randomization on
break opaque.c:79
run
printf "UD=%p UNP=%p FN=%p UNPSIZE=%d\n", ud, ud->unpacked_data, ud->destroy_unpacked_func_ptr, ud->unpacked_size
break *0x555555661b30
continue
printf "CHOICE_RIP=%p RDI=%p RSI=%p RDX=%d\n", $pc, $rdi, $rsi, $rdx
printf "S=%p STR=%p ALLOC=%d LEN=%d\n", s, s->str, s->alloc_size, s->length
x/2gx s->str - 8
bt 3
break free
continue
printf "FREE_RDI=%p\n", $rdi
quit
