set pagination off
set confirm off
set print thread-events off
set print elements 0
break dtls13.c:2604 if ackMessage + 8 > output + headerLength + 2 + msgSz
printf "FACT BREAK first-OOB-epoch-write\n"
run 18630 1 1 1
printf "FACT FIRST_OOB output=%p region_end=%p ackMessage=%p msgSz=%d hdr=%d\n", output, output + headerLength + 2 + msgSz, ackMessage, msgSz, headerLength
printf "FACT KEY ssl=%p ctx=%p in=%p seen=%p encEp=%p decEp=%p rtx=%p\n", ssl, ssl->ctx, ssl->buffers.inputBuffer.buffer, ssl->dtls13Rtx.seenRecords, ssl->dtls13EncryptEpoch, ssl->dtls13DecryptEpoch, ssl->dtls13Rtx.rtxRecords
printf "FACT SEEN n0=%p n1=%p n2=%p\n", ssl->dtls13Rtx.seenRecords, ssl->dtls13Rtx.seenRecords->next, ssl->dtls13Rtx.seenRecords->next->next
printf "FACT MEM_128QWORDS_AFTER_REGION:\n"
x/128gx output + headerLength + 2 + msgSz
printf "FACT CHUNK_HDRS_FROM_OUTPUT:\n"
x/48gx output + 16
printf "FACT MAPS:\n"
info proc mappings
delete 1
break dtls13.c:2613
continue
printf "FACT POST_LOOP ackMessage=%p length=%u outbuf=%p size=%u\n", ackMessage, *length, ssl->buffers.outputBuffer.buffer, ssl->buffers.outputBuffer.bufferSize
printf "FACT POST_MEM_64QWORDS:\n"
x/64gx output + headerLength + 2 + msgSz
kill
