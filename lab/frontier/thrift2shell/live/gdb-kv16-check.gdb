set pagination off
set confirm off
set print pretty off
break THeaderTransport.cpp:301
commands 1
 silent
 printf "AT301 ptr=%p sz=%u tbuf=%p\n", ptr, sz, tBuf_.get()
 x/8bx ptr+24
 x/8bx tBuf_.get()+24
 continue
end
break THeaderTransport.cpp:307
commands 2
 silent
 printf "AT307 ptr=%p sz=%u rbuf=%p\n", ptr, sz, rBuf_.get()
 x/8bx ptr+24
 quit
end
run
