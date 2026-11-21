set pagination off
set confirm off
set print pretty off
break crawler.c:310 if cm->c.bufused + 260 >= 131072
run -l 127.0.0.1 -p 22126 -U 0 -m 64 -u mesh-home -o lru_crawler_sleep=0
disable 1
set $buf = cm->c.buf
set $bufend = cm->c.buf + 131072
printf "NEAR_END bufused=%d nkey=%u buf=%p bufend=%p\n", cm->c.bufused, it->nkey, $buf, $bufend
break util.c:57 if dst + d >= $bufend
continue
printf "OOB_WRITE addr=%p delta=%ld srcbyte=0x%02x d=%lu srclen=%lu\n", dst+d, (long)(dst+d-$bufend), (unsigned char)src[x], d, srclen
printf "MEMORY -32..+96 around end:\n"
x/128bx $bufend-32
printf "CURL BUF tail @ -16:\n"
x/16bx $bufend-16
bt 5
quit
