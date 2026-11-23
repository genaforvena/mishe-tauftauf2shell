set pagination off
set confirm off
handle SIGPIPE nostop noprint pass
break fifo.c:61 if nb_elems == 8388608
run -hide_banner -loglevel verbose -f data -i async:rist://@:5004 -show_packets
printf "BUFFER nb_elems=%zu buffer=%p\n", nb_elems, buffer
finish
printf "FIFO struct=%p\n", f
quit
