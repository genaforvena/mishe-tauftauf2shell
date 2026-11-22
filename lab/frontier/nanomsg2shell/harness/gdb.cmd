set pagination off
set confirm off
break ws_handshake.c:1350
run
next
printf "RESP_LEN=%zu\n", strlen(self->response)
printf "DONE_BYTES:\n"
x/32cb &self->done
printf "DONE_WORDS:\n"
x/8gx &self->done
kill
quit
