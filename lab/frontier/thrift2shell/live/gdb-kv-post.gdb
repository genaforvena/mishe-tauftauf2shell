set pagination off
set confirm off
set print pretty off
break THeaderTransport.cpp:301
commands 1
 silent
 printf "PRE ptr=%p sz=%u rbuf=%p tbuf=%p delta=%ld\n", ptr, sz, rBuf_.get(), tBuf_.get(), (long)(tBuf_.get()-rBuf_.get())
 dump binary memory results/kv-post-heap.bin rBuf_.get() rBuf_.get()+1100
 continue
end
break THeaderTransport.cpp:307
commands 2
 silent
 printf "POST tcache_count1=%d tcache_entry1=%p\n", tcache->counts[1], tcache->entries[1]
 dump binary memory results/kv-post-after.bin rBuf_.get() rBuf_.get()+1100
 continue
end
run
printf "ABORT tcache_count1=%d tcache_entry1=%p\n", tcache->counts[1], tcache->entries[1]
x/8gx &tcache->entries[0]
bt 25
