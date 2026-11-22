set pagination off
set confirm off
set breakpoint pending on
shell cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/nanomsg2shell && (python3 harness/wire_pattern.py 490 cycle 3 > harness/release/client-nofort-cycle.txt 2>&1 &)
break ws_handshake.c:1350
run
printf "=== at sprintf line 1350 ===\n"
p (int)((char *)&((struct nn_ws_handshake *)0)->done - (char *)&((struct nn_ws_handshake *)0)->response)
printf "PRE item.next = "
p/x self->done.item.next
break ws_handshake.c:1358
continue
printf "=== after sprintf, line 1358 ===\n"
printf "SELF=%p RESP=%p DONE=%p DONE_OFFSET=%ld\n", self, self->response, &self->done, (char *)&self->done - (char *)self->response
printf "VERSION_LEN=%zu RESPONSE_CODE=%d\n", self->version_len, self->response_code
x/s self->response
printf "--- done 40 bytes ---\n"
x/40cb &self->done
printf "POST item.next = "
p/x self->done.item.next
kill
quit
