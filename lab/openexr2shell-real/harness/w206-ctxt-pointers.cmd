# W206: resolve every function pointer in _priv_exr_context_t bytes 0..103
# at the pinned opaque.c:79 call, ASLR off.  The 104-byte W202 memcpy covers
# these fields; ctxt->free_fn (+96) is only one of them.
set pagination off
set confirm off
set disable-randomization on
break opaque.c:79
run
printf "CTXT=%p\n", ctxt
x/13gx ctxt
printf "P0=%p P1=%p P2=%p P3=%p\n", *(void**)((char*)ctxt+40), *(void**)((char*)ctxt+48), *(void**)((char*)ctxt+56), *(void**)((char*)ctxt+64)
printf "P4=%p P5=%p P6=%p P7=%p\n", *(void**)((char*)ctxt+72), *(void**)((char*)ctxt+80), *(void**)((char*)ctxt+88), *(void**)((char*)ctxt+96)
info symbol *(void**)((char*)ctxt+40)
info symbol *(void**)((char*)ctxt+48)
info symbol *(void**)((char*)ctxt+56)
info symbol *(void**)((char*)ctxt+64)
info symbol *(void**)((char*)ctxt+72)
info symbol *(void**)((char*)ctxt+80)
info symbol *(void**)((char*)ctxt+88)
info symbol *(void**)((char*)ctxt+96)
printf "FILENAME_PTR=%p TMP_PTR=%p\n", *(void**)((char*)ctxt+8), *(void**)((char*)ctxt+24)
quit
