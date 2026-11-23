set pagination off
set confirm off
handle SIGPIPE nostop noprint pass
set detach-on-fork off
break librist_read
run -hide_banner -loglevel verbose -f data -i async:rist://@:5004 -show_packets
printf "CC H=%p prot=%p\n", h, h->prot
python import gdb; gdb.execute("set $protaddr = %#x" % (int(gdb.parse_and_eval("h")) + 8))
python import gdb; gdb.execute("set $uc = %#x" % int(gdb.parse_and_eval("h")))
disable 1
watch -l *(uint8_t **)$protaddr
continue
printf "CC FIRST HIT prot=%p\n", *(void **)$protaddr
disable 2
break system
continue
printf "CC NEXT STOP\n"
bt 6
printf "CC callback=%p cmd=%s\n", *(void **)($uc+0x30), (char*)($uc+0x50)
quit
