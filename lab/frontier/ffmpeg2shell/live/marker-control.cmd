set pagination off
set confirm off
handle SIGPIPE nostop noprint pass
break librist_read
run -hide_banner -loglevel verbose -f data -i async:rist://@:5004 -show_packets
printf "MC H=%p prot=%p\n", h, h->prot
python import gdb; gdb.execute("set $protaddr = %#x" % (int(gdb.parse_and_eval("h")) + 8))
python import gdb; gdb.execute("set $uc = %#x" % int(gdb.parse_and_eval("h")))
disable 1
watch -l *(uint8_t **)$protaddr
continue
printf "MC FIRST HIT prot=%p callback=%p opaque=%p str=%s\n", \
    *(void **)$protaddr, *(void **)($uc+0x30), *(void **)($uc+0x38), (char*)($uc+0x50)
disable 2
break puts
continue
printf "MC NEXT STOP\n"
bt 6
printf "MC callback=%p opaque=%p str=%s prot=%p\n", \
    *(void **)($uc+0x30), *(void **)($uc+0x38), (char*)($uc+0x50), *(void **)$protaddr
quit
