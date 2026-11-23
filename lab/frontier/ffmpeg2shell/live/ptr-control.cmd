set pagination off
set confirm off
handle SIGPIPE nostop noprint pass
break librist_read
run -hide_banner -loglevel verbose -f data -i async:rist://@:5004 -show_packets
printf "PC H=%p prot=%p\n", h, h->prot
python import gdb; gdb.execute("set $protaddr = %#x" % (int(gdb.parse_and_eval("h")) + 8))
disable 1
watch -l *(uint8_t **)$protaddr
continue
printf "PC FIRST HIT new=%p\n", *(void **)$protaddr
disable 2
break file_read
enable 1
continue
printf "PC NEXT STOP\n"
bt 6
printf "PC prot=%p url_read=%p file_read=%p\n", \
    *(void **)$protaddr, *(void **)(*(char **)$protaddr + 0x28), &file_read
quit
