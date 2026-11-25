# W202: prove the file-carried indirect call at opaque.c:79 is libc memcpy,
# that it rewrites ctxt->free_fn, and that the consumer then calls system()
# with a file-carried command string.  ASLR OFF so absolute addresses carry.
set pagination off
set confirm off
set disable-randomization on
break opaque.c:79
run
printf "CTXT=%p FREEFN_BEFORE=%p UNP=%p SZ=%d TARGET=%p\n", ctxt, ctxt->free_fn, ud->unpacked_data, ud->unpacked_size, ud->destroy_unpacked_func_ptr
break *0x7ffff7feb900
continue
printf "MEMCPY_RDI=%p RSI=%p RDX=%ld SRC_FREEFN=%p\n", $rdi, $rsi, $rdx, *(void**)($rsi+96)
break __libc_system
continue
printf "SYSTEM_RDI=%p\n", $rdi
x/s $rdi
x/gx 0x555555826f60
continue
quit
