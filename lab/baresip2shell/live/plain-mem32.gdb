set pagination off
set confirm off
break websock.c:216 if i == 0
break websock.c:216 if i == 32
run
printf "STOP0 P=%p MB_BUF=%p MB_SIZE=%lu MB_END=%lu KEY=%02x%02x%02x%02x\n", p, mb->buf, (unsigned long)mb->size, (unsigned long)mb->end, hdr->mkey[0], hdr->mkey[1], hdr->mkey[2], hdr->mkey[3]
printf "BEFORE_OOB:\n"
x/48xb p
set $oob = p
continue
printf "STOP32_I=%lu\n", (unsigned long)i
printf "AFTER_32_XOR_ITERATIONS:\n"
x/48xb $oob
quit
