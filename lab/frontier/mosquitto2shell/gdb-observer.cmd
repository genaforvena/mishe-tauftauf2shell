set pagination off
set confirm off
set disable-randomization off
set environment LD_LIBRARY_PATH /home/mesh-home/mishe-tauftauf2shell/lab/frontier/mosquitto2shell/deps/cjson-stock-prefix/lib
set breakpoint pending on

break packet_mosq.c:564
commands
 silent
 printf "PAYLOAD mosq=%p ptr=%p len=%u\n", mosq, mosq->in_packet.payload, mosq->in_packet.remaining_length
 continue
end

break net_ws.c:67
commands
 silent
 printf "PREPARE pkt=%p payload=%p plen=%u\n", packet, &packet->payload[0], packet->packet_length
 continue
end

break memcpy if $rdx >= 10 && $rdx <= 40
commands
 silent
 printf "MEMCPY dst=%p src=%p len=%lu\n", $rdi, $rsi, $rdx
 continue
end

run -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/mosquitto2shell/run/groom-27081.conf -v
