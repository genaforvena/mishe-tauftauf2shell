set pagination off
set confirm off
handle SIGPIPE nostop noprint pass
break async.c:89
run -hide_banner -loglevel verbose -f data -i async:rist://@:5004 -show_packets
printf "INIT buffer=%p\n", ring->fifo->buffer
watch -l ring->fifo->buffer
continue
printf "WATCH HIT\n"
bt 10
info registers rip rdi rsi rdx
quit
