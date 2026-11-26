# W211: file-carried stream-mode chain attribution. ASLR OFF so the absolute
# pointers in the EXR are meaningful; gdb only sets breakpoints.
set pagination off
set confirm off
set disable-randomization on
break sort2_4ByteChannels_tiled
run
set $dest = (long)outPtr + 3072
printf "DEST=%p\n", (void*)$dest
break attributes.c:305
continue
printf "SLOT_ADDR=%p SLOT=%p REL=%ld\n", &list->entries[0], list->entries[0], (long)&list->entries[0]-$dest
break opaque.c:79
continue
printf "CTXT=%p FREEFN_BEFORE=%p UNP=%p SZ=%d TARGET=%p\n", ctxt, ctxt->free_fn, ud->unpacked_data, ud->unpacked_size, ud->destroy_unpacked_func_ptr
break *0x7ffff7feb900
continue
printf "MEMCPY_RDI=%p RSI=%p RDX=%ld SRC_FREEFN=%p\n", $rdi, $rsi, $rdx, *(void**)($rsi+96)
break __libc_system
continue
printf "SYSTEM_RDI=%p\n", $rdi
x/s $rdi
continue
quit
