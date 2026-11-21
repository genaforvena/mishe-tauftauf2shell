# Dump the buf+6144 neighbour AFTER the F5 realloc but BEFORE the F6 write.
# F1 consumes len 8; F2..F5 each consume len 1438.  The 4th len==1438 is F5,
# whose realloc has already produced the final 5762-byte pers_inbuf buffer.
set pagination off
set confirm off
cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
set $n1438 = 0
break wire_buf_consume
commands
  silent
  if $rsi == 1438
    set $n1438 = $n1438 + 1
    if $n1438 == 4
      set $wb = $rdi
      set $buf = *(unsigned long*)$wb
      set $slot1 = $buf + 6144
      printf "PRE-F6 buf=0x%lx slot1=0x%lx len=%lu size=%lu\n", \
        $buf, $slot1, $rsi, *(unsigned long*)($wb+8)
      frame 1
      set $ng = ngconn
      frame 0
      printf "PRE-F6 ngconn=0x%lx tls_native_handle=0x%lx match=%d\n", \
        (unsigned long)$ng, *(unsigned long*)((char*)$ng+7648), \
        (int)(*(unsigned long*)((char*)$ng+7648) == $slot1)
      printf "PRE-F6 in_pktns=0x%lx hs_pktns=0x%lx embedded=0x%lx\n", \
        *(unsigned long*)((char*)$ng+656), *(unsigned long*)((char*)$ng+664), \
        (unsigned long)($ng+672)
      x/48gx $slot1
    end
  end
  continue
end
run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
printf "STOP: rip=%p\n", $pc
