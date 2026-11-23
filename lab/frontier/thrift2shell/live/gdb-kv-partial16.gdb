set pagination off
set confirm off
set print pretty off
set breakpoint pending on
set disable-randomization off
break THeaderTransport.cpp:301
commands 1
 silent
 printf "PRE ptr=%p sz=%u rbuf=%p tbuf=%p\n", ptr, sz, rBuf_.get(), tBuf_.get()
 continue
end
break THeaderTransport.cpp:307
commands 2
 silent
 printf "POST rbuf=%p target=%p\n", rBuf_.get(), *(void**)(rBuf_.get()+464)
 continue
end
break __libc_free
commands 3
 silent
 printf "FREE mem=%p\n", $rdi
 continue
end
run
printf "END\n"
bt 18
