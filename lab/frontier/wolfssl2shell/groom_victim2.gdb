set pagination off
set confirm off
set print thread-events off
set print elements 0
break dtls13.c:2613
printf "FACT BREAK post-loop\n"
run 18633 60 1 1 64
printf "FACT POST out=%p wend=%p ackMessage=%p outbuf_size=%u\n", output, output + headerLength + 2 + msgSz, ackMessage, ssl->buffers.outputBuffer.bufferSize
printf "FACT HEAD=%p\n", ssl->dtls13Rtx.seenRecords
printf "FACT HEAD_MEM (chunk hdr + 24 bytes):\n"
x/8gx ssl->dtls13Rtx.seenRecords - 16
printf "FACT NODES_MEM 256 bytes from head:\n"
x/32gx ssl->dtls13Rtx.seenRecords
printf "FACT OUTBUF_MEM 128 bytes:\n"
x/16gx output
printf "FACT frames:\n"
bt 5
kill
