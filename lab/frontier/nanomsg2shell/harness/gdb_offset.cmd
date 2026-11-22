set pagination off
set confirm off
set breakpoint pending on
shell cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/nanomsg2shell && (python3 harness/wire_pattern.py 490 cycle 2 > harness/client-cycle-490.txt 2>&1 &)
break nn_ws_handshake_server_reply
run
break ws_handshake.c:1355
continue
printf "SELF=%p RESP=%p DONE=%p DONE_OFFSET=%ld\n", self, self->response, &self->done, (char *)&self->done - (char *)self->response
printf "VERSION_LEN=%zu RESPONSE_CODE=%d\n", self->version_len, self->response_code
x/s self->response
printf "--- response+512 .. +551 (40 bytes past the fixed field) ---\n"
x/48cb self->response + 512
printf "--- done (40 bytes) ---\n"
x/40cb &self->done
printf "--- done as words ---\n"
x/5gx &self->done
printf "--- item.next ---\n"
p/x self->done.item.next
kill
quit
