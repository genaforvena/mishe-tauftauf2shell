set pagination off
set confirm off
set environment LD_LIBRARY_PATH /home/mesh-home/mishe-tauftauf2shell/lab/frontier/mosquitto2shell/deps/cjson-stock-prefix/lib
set breakpoint pending on

break packet_mosq.c:564
commands
 silent
 printf "PAYLOAD mosq=%p ptr=%p len=%u\n", mosq, mosq->in_packet.payload, mosq->in_packet.remaining_length
 continue
end

break net_ws.c:282
commands
 silent
 continue
end

break net_ws.c:288
commands
 silent
 if mosq->wsd.out_packet != 0
   printf "PONG mosq=%p pkt=%p payload=%p plen=%u\n", mosq, mosq->wsd.out_packet, &mosq->wsd.out_packet->payload[0], mosq->wsd.out_packet->packet_length
 end
 continue
end

break net_ws.c:67
commands
 silent
 printf "PREPARE pkt=%p payload=%p plen=%u\n", packet, &packet->payload[0], packet->packet_length
 continue
end

run -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/mosquitto2shell/run/groom-27081.conf -v
