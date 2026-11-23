set pagination off
set confirm off
handle SIGPIPE nostop noprint pass
break librist_read
run -hide_banner -loglevel verbose -f data -i async:rist://@:5004 -show_packets
printf "RP H=%p prot=%p\n", h, h->prot
python import gdb; gdb.execute("set $protaddr = %#x" % (int(gdb.parse_and_eval("h")) + 8))
disable 1
watch -l *(uint8_t **)$protaddr
continue
printf "RP FIRST HIT new=%p\n", *(void **)$protaddr
disable 2
break ffurl_read2
continue
printf "RP NEXT DISPATCH prot=%p\n", *(void **)$protaddr
bt 6
quit
