set pagination off
set confirm off
set print thread-events off
break dtls13.c:2607 if ackMessage > output + headerLength + 2 + msgSz
printf "FACT BREAK set at post-write OOB\n"
run 18520 1 1 1
printf "FACT OOB ackMessage=%p output=%p hdr=%d msgSz=%d region_end=%p\n", ackMessage, output, headerLength, msgSz, output + headerLength + 2 + msgSz
printf "FACT current epoch=%llu seq=%llu\n", recordNumberList->epoch.n, recordNumberList->seq.n
printf "FACT markers_at_and_past_region:\n"
x/32bx output + headerLength + 2 + msgSz - 8
printf "FACT glibc_chunk_headers (output-16, output+16, output+32):\n"
x/12gx output - 16
printf "FACT buffer pointers:\n"
printf "FACT input=%p output=%p seenRecords=%p curNode=%p outBuf=%p\n", ssl->buffers.inputBuffer.buffer, output, ssl->dtls13Rtx.seenRecords, recordNumberList, ssl->buffers.outputBuffer.buffer
printf "FACT frames:\n"
bt 6
kill
