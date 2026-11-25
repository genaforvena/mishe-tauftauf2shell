# W209: stop after the expansion loop on the 205-byte attack and read the
# live FILE fields overwritten by the file-chosen subnormal word.
set pagination off
set confirm off
break stb_vorbis.h:4054 if f->stream_len == 205
run
set $clamp = *(void**)((char*)f->io+56)
set $fileio = *(void**)$clamp
set $iodata = *(void**)((char*)$fileio+56)
set $filep = *(void**)$iodata
printf "CANON_POST mult=%p file=%p save_base=%p backup_base=%p save_end=%p\n", c->multiplicands, $filep, ((struct _IO_FILE*)$filep)->_IO_save_base, ((struct _IO_FILE*)$filep)->_IO_backup_base, ((struct _IO_FILE*)$filep)->_IO_save_end
x/s ((struct _IO_FILE*)$filep)->_IO_save_base
quit
