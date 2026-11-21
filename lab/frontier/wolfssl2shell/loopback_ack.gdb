set pagination off
set confirm off
break Dtls13RecordRecvd
commands
silent
printf "HIT Dtls13RecordRecvd type=%d stateful=%d seen=%d\n", ssl->curRL.type, ssl->options.dtlsStateful, ssl->dtls13Rtx.seenRecords != 0
continue
end
break Dtls13RtxAddAck
commands
silent
printf "HIT Dtls13RtxAddAck\n"
continue
end
break Dtls13WriteAckMessage
commands
silent
printf "HIT Dtls13WriteAckMessage\n"
continue
end
break Dtls13RtxFlushAcks
commands
silent
printf "HIT Dtls13RtxFlushAcks\n"
continue
end
run 18458
