set pagination off
set confirm off
set print thread-events off
break DtlsShouldDrop
commands
silent
printf "HIT DtlsShouldDrop type=%d done=%d ver=%d\n", ssl->curRL.type, ssl->options.handShakeDone, ssl->version.minor
continue
end
break DropAndRestartProcessReply
commands
silent
printf "HIT DropAndRestart type=%d\n", ssl->curRL.type
continue
end
break Dtls13CheckWindow
commands
silent
printf "HIT CheckWindow stateful=%d done=%d\n", ssl->options.dtlsStateful, ssl->options.handShakeDone
continue
end
break Dtls13UpdateWindowRecordRecvd
commands
silent
printf "HIT UpdWindowRecvd type=%d stateful=%d\n", ssl->curRL.type, ssl->options.dtlsStateful
continue
end
break Dtls13RecordRecvd
commands
silent
printf "HIT RecordRecvd type=%d\n", ssl->curRL.type
continue
end
break Dtls13RtxAddAck
commands
silent
printf "HIT AddAck\n"
continue
end
break Dtls13RtxMsgRecvd
commands
silent
printf "HIT RtxMsgRecvd hs=%d fragOff=%d\n", hs, fragOffset
continue
end
break Dtls13AcceptFragmented
commands
silent
printf "HIT AcceptFrag\n"
continue
end
run 18512 1 1
