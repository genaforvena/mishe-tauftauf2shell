set pagination off
set confirm off
set print pretty off
break THeaderTransport.cpp:301
commands 1
 silent
 printf "PRE ptr=%p sz=%u rbuf=%p rbufsz=%u tbuf=%p delta=%ld\n", ptr, sz, rBuf_.get(), rBufSize_, tBuf_.get(), (long)(tBuf_.get()-rBuf_.get())
 dump binary memory results/kv-heap.bin rBuf_.get() rBuf_.get()+1100
 continue
end
run
