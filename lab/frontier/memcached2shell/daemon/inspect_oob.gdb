set pagination off
set confirm off
set print pretty off
break crawler.c:310 if cm->c.bufused + 260 >= 131072
run -l 127.0.0.1 -p 22124 -U 0 -m 64 -u mesh-home -o lru_crawler_sleep=0
disable 1
printf "HIT310 bufused=%d nkey=%u p=%p buf=%p\n", cm->c.bufused, it->nkey, p, cm->c.buf
set $bufend = cm->c.buf + 131072
printf "BUFEND=%p p_delta_from_end=%ld\n", $bufend, (long)(p - $bufend)
break util.c:57 if dst + d >= $bufend
continue
printf "OOB_WRITE addr=%p delta=%ld srcbyte=0x%02x d=%lu srclen=%lu\n", dst+d, (long)(dst+d-$bufend), (unsigned char)src[x], d, srclen
bt 5
quit
