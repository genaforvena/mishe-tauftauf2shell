set pagination off
set confirm off
set print thread-events off
set print elements 0
break dtls13.c:2613
printf "FACT BREAK post-loop\n"
run 18632 60 1 1 64
printf "FACT POST out=%p wend=%p ackMessage=%p msgSz=%d hdr=%d outbuf_size=%u\n", output, output + headerLength + 2 + msgSz, ackMessage, msgSz, headerLength, ssl->buffers.outputBuffer.bufferSize
printf "FACT KEY ssl=%p in=%p seen=%p encEp=%p\n", ssl, ssl->buffers.inputBuffer.buffer, ssl->dtls13Rtx.seenRecords, ssl->dtls13EncryptEpoch
printf "FACT NODES n0=%p n1=%p n2=%p n3=%p\n", ssl->dtls13Rtx.seenRecords, ssl->dtls13Rtx.seenRecords->next, ssl->dtls13Rtx.seenRecords->next->next, ssl->dtls13Rtx.seenRecords->next->next->next
printf "FACT NEXT_FIELDS n0next=%p n1next=%p n2next=%p\n", ssl->dtls13Rtx.seenRecords->next, ssl->dtls13Rtx.seenRecords->next->next, ssl->dtls13Rtx.seenRecords->next->next->next
printf "FACT NODE0_MEM:\n"
x/24gx ssl->dtls13Rtx.seenRecords - 16
printf "FACT OUTBUF_MEM:\n"
x/48gx output
printf "FACT frames:\n"
bt 5
kill
