set pagination off
set confirm off
set print pretty off
break THeaderTransport.cpp:301
commands 1
 silent
 dump binary memory results/kv-ptr-tbuf.bin tBuf_.get() tBuf_.get()+800
 dump binary memory results/kv-ptr-heap.bin rBuf_.get() rBuf_.get()+1100
 continue
end
run
p tcache->counts[1]
p tcache->entries[1]
bt 5
