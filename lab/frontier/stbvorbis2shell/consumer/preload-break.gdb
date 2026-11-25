# W208: drive a valid audio preload, then stop on the 205-byte attack.
# The preload leaves the attack FILE object immediately after the truncated
# multiplicands allocation. Watch its live _IO_save_base pointer change.
set pagination off
set confirm off
break stb_vorbis.h:4043 if f->stream_len == 205
break stb_vorbis.h:4054 if f->stream_len == 205
run
set $clamp = *(void**)((char*)f->io+56)
set $fileio = *(void**)$clamp
set $iodata = *(void**)((char*)$fileio+56)
set $filep = *(void**)$iodata
printf "W208_PRE mult=%p file=%p delta=%ld\n", c->multiplicands, $filep, (char*)$filep-(char*)c->multiplicands
x/16gx $filep
watch -l ((struct _IO_FILE*)$filep)->_IO_save_base
continue
printf "W208_STORE_LOW pc=%p j=%d k=%d save_base=%p\n", $pc, j, k, ((struct _IO_FILE*)$filep)->_IO_save_base
x/i $pc
bt 6
continue
printf "W208_STORE_HIGH pc=%p j=%d k=%d save_base=%p\n", $pc, j, k, ((struct _IO_FILE*)$filep)->_IO_save_base
continue
printf "W208_POST mult=%p file=%p save_base=%p backup_base=%p save_end=%p\n", c->multiplicands, $filep, ((struct _IO_FILE*)$filep)->_IO_save_base, ((struct _IO_FILE*)$filep)->_IO_backup_base, ((struct _IO_FILE*)$filep)->_IO_save_end
x/16gx $filep
continue
bt 10
quit
