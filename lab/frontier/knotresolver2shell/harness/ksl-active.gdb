# Rung-4 probe: place an ACTIVE pktns in the +6144 neighbour, overwrite its
# ngtcp2_ksl comparator with chosen bytes, then watch for a dispatch through it.
set pagination off
set confirm off
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/harness/ksl-active.txt
set logging overwrite on
set logging redirect on
set logging enabled on
cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
set $slot1 = 0
set $seen = 0
set $hits = 0

break wire_buf_consume
commands
  silent
  set $wb  = (unsigned long)$rdi
  set $len = (unsigned long)$rsi
  if $len == 1198 && $seen == 0
    set $seen = 1
    set $buf = *(unsigned long*)$wb
    set $slot1 = $buf + 6144
    printf "F6 buf=0x%lx slot1=0x%lx len=%lu size=%lu\n", $buf, $slot1, $len, *(unsigned long*)($wb + 8)
    printf "F6 ksl=%p compar=%p search=%p n=%lu keylen=%lu\n", $slot1+0x48, *(void**)($slot1+0xa0), *(void**)($slot1+0xa8), *(unsigned long*)($slot1+0xb0), *(unsigned long*)($slot1+0xb8)
    x/8gx $slot1+0x80
    rwatch -l *(unsigned long*)($slot1+0xa0)
    printf "F6 read-watchpoint armed on %p\n", $slot1+0xa0
  end
  continue
end

break ngtcp2_ksl_insert if $slot1 != 0
commands
  silent
  if *(unsigned long*)($rdi+0x58) == 0x4141414141414141
    set $hits = $hits + 1
    printf "DISPATCH HIT #%lu ksl=%p compar=%p\n", $hits, $rdi, *(unsigned long*)($rdi+0x58)
    x/4gx $rdi+0x50
  else
    printf "ksl-insert other ksl=%p compar=%p\n", $rdi, *(unsigned long*)($rdi+0x58)
  end
  continue
end

run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
printf "STOP: rip=%p hits=%lu\n", $pc, $hits
info registers rip rdi rsi
bt 14
