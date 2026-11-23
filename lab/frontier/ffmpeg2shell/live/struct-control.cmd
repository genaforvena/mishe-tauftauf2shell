set pagination off
set confirm off
handle SIGPIPE nostop noprint pass
break librist_read
run -hide_banner -loglevel verbose -f data -i async:rist://@:5004 -show_packets
printf "SC H=%p prot=%p\n", h, h->prot
python import gdb; gdb.execute("set $protaddr = %#x" % (int(gdb.parse_and_eval("h")) + 8))
python import gdb; gdb.execute("set $fifoaddr = %#x" % (int(gdb.parse_and_eval("h")) - 0x40))
disable 1
watch -l *(uint8_t **)$protaddr
continue
printf "SC FIRST HIT prot=%p\n", *(void **)$protaddr
disable 2
break file_read
enable 1
continue
printf "SC NEXT STOP\n"
bt 6
printf "SC prot=%p fifo.buffer=%p fifo.nb=%lu\n", \
    *(void **)$protaddr, *(void **)$fifoaddr, *(unsigned long *)($fifoaddr+0x10)
quit
