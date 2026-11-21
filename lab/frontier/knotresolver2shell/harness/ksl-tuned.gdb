# Tuned-drift oracle: identify the +6144 neighbour for N=5,D=1225 geometry.
set pagination off
set confirm off
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/harness/ksl-tuned.txt
set logging overwrite on
set logging redirect on
set logging enabled on
cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
set $seen = 0
set $slot1 = 0
break wire_buf_consume
commands
  silent
  set $wb = (unsigned long)$rdi
  set $len = (unsigned long)$rsi
  set $siz = *(unsigned long*)($wb+8)
  if $len == 1200 && $siz == 7325 && $seen == 0
    set $seen = 1
    set $buf = *(unsigned long*)$wb
    set $slot1 = $buf + 6144
    printf "F6 buf=%p slot1=%p len=%lu tracked=%lu\n", $buf, $slot1, $len, $siz
    printf "gap-ksl=%p compar=%p search=%p n=%lu keylen=%lu\n", $slot1+0x48, *(void**)($slot1+0xa0), *(void**)($slot1+0xa8), *(unsigned long*)($slot1+0xb0), *(unsigned long*)($slot1+0xb8)
    printf "acktr-ksl=%p compar=%p search=%p n=%lu keylen=%lu\n", $slot1+0x388, *(void**)($slot1+0x3e0), *(void**)($slot1+0x3e8), *(unsigned long*)($slot1+0x3f0), *(unsigned long*)($slot1+0x3f8)
    x/32gx $slot1+0x80
    x/8gx $slot1+0x380
    rwatch -l *(unsigned long*)($slot1+0xa0)
    rwatch -l *(unsigned long*)($slot1+0x3e0)
    printf "watchpoints armed\n"
  end
  continue
end
break ngtcp2_ksl_insert if $slot1 != 0
commands
  silent
  if *(unsigned long*)($rdi+0x58) == 0x4141414141414141
    printf "DISPATCH HIT ksl=%p compar=%p\n", $rdi, *(unsigned long*)($rdi+0x58)
  end
  continue
end
run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
printf "STOP rip=%p\n", $pc
bt 12
