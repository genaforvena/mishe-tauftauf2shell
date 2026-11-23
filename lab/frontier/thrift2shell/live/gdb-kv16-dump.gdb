set pagination off
set confirm off
set print pretty off
break THeaderTransport.cpp:307
commands 1
 silent
 printf "RBUF=%p PTR=%p SZ=%u TBUF=%p\n", rBuf_.get(), ptr, sz, tBuf_.get()
 x/8gx rBuf_.get()+440
 x/8gx tBuf_.get()+48
 quit
end
run
