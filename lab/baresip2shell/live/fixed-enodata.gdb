set pagination off
set confirm off
break websock.c:207
run
printf "SEEN_LEN_HEX=%lx\n", hdr->len
printf "LEFT_BEFORE=%lu\n", (unsigned long) mbuf_get_left(mb)
finish
printf "DECODE_RETURN=%d\n", $rax
quit
