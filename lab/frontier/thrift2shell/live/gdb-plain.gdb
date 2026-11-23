set pagination off
set confirm off
set print pretty off
break THeaderTransport.cpp:301
commands 1
 silent
 printf "PRE ptr=%p sz=%u rbuf=%p rbufsz=%u tbuf=%p tbufsz=%u delta=%ld\n", ptr, sz, rBuf_.get(), rBufSize_, tBuf_.get(), tBufSize_, (long)(tBuf_.get()-rBuf_.get())
 x/2gx rBuf_.get()-16
 x/2gx tBuf_.get()-16
 x/16bx ptr
 continue
end
break THeaderTransport.cpp:307
commands 2
 silent
 printf "POST ptr=%p sz=%u rbuf=%p tbuf=%p\n", ptr, sz, rBuf_.get(), tBuf_.get()
 x/16bx ptr
 x/8bx ptr+26
 x/8bx ptr+42
 x/gx tBuf_.get()-16
 x/gx tBuf_.get()-8
 x/8bx tBuf_.get()
 x/2gx rBuf_.get()-16
 continue
end
run
