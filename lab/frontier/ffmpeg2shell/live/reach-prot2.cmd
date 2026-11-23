set pagination off
set confirm off
handle SIGPIPE nostop noprint pass
break librist_read
run -hide_banner -loglevel verbose -f data -i async:rist://@:5004 -show_packets
printf "R2 H=%p prot=%p\n", h, h->prot
python import gdb; gdb.execute("set $protaddr = %#x" % (int(gdb.parse_and_eval("h")) + 8))
disable 1
watch -l *(uint8_t **)$protaddr
continue
printf "R2 WATCH HIT old=%p new=%p\n", \
    ((uint8_t **)$protaddr)[0], ((uint8_t **)$protaddr)[0]
disable 2
set *(void **)$protaddr = &ff_file_protocol
printf "R2 SET prot=%p\n", *(void **)$protaddr
break ffurl_read2
break file_read
continue
printf "R2 NEXT STOP\n"
bt 6
printf "R2 prot now=%p url_read=%p file_read=%p\n", \
    *(void **)$protaddr, (*(void ***)($protaddr))[1], &file_read
quit
