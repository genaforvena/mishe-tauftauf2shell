set pagination off
set confirm off
handle SIGPIPE nostop noprint pass
break librist_read
run -hide_banner -loglevel verbose -f data -i async:rist://@:5004 -show_packets
printf "LIBRIST H=%p prot=%p priv=%p\n", h, h->prot, h->priv_data
disable 1
watch -l *(uint8_t **)(0x5555560d2088)
continue
printf "PROT WATCH HIT\n"
bt 8
x/4gx 0x5555560d2080
quit
