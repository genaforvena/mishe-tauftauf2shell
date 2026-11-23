set pagination off
set confirm off
handle SIGPIPE nostop noprint pass
break librist_read
run -hide_banner -loglevel verbose -f data -i async:rist://@:5004 -show_packets
printf "REACH H=%p prot=%p priv=%p\n", h, h->prot, h->priv_data
python import gdb; gdb.execute("set $protaddr = %#x" % (int(gdb.parse_and_eval("h")) + 8))
printf "REACH protaddr=%p\n", $protaddr
disable 1
watch -l *(uint8_t **)$protaddr
break file_read
continue
printf "REACH WATCH HIT at %p\n", $protaddr
bt 8
x/4gx $protaddr-8
set *(void **)$protaddr = &ff_file_protocol
printf "REACH SET prot=%p (wanted %p)\n", *(void **)$protaddr, &ff_file_protocol
continue
printf "REACH AFTER CONTINUE\n"
bt 12
quit
