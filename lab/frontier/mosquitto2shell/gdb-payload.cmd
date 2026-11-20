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

run -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/mosquitto2shell/run/groom-27081.conf -v
