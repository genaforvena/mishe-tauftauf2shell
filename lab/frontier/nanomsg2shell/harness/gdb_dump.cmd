set pagination off
set confirm off
set breakpoint pending on
break nn_ws_handshake_server_reply
run
break ws_handshake.c:1355
continue
printf "VERSION_LEN=%zu RESPONSE_CODE=%d\n", self->version_len, self->response_code
printf "SELF=%p RESP=%p DONE=%p DONE_OFFSET=%ld\n", self, self->response, &self->done, (char *)&self->done - (char *)self->response
printf "--- done (40 bytes) ---\n"
x/40cb &self->done
printf "--- done as words ---\n"
x/5gx &self->done
printf "--- item.next ---\n"
p/x self->done.item.next
kill
quit
