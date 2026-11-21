# Rung-4 probe: F6 OOB body overwrites the live ngtcp2_ksl comparator.
# Capture slot1 at the F6 consume, log the new compar, arm a read watchpoint.
set pagination off
set confirm off
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/harness/ksl-control.txt
set logging overwrite on
set logging redirect on
set logging enabled on
cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
set $seen = 0
break wire_buf_consume
commands
  silent
  set $wb  = (unsigned long)$rdi
  set $len = (unsigned long)$rsi
  set $siz = *(unsigned long*)($wb + 8)
  if $len == 1198 && $seen == 0
    set $seen = 1
    set $buf = *(unsigned long*)$wb
    set $slot1 = $buf + 6144
    printf "F6 buf=0x%lx slot1=0x%lx len=%lu size=%lu\n", $buf, $slot1, $len, $siz
    printf "F6 root=%p front=%p back=%p\n", *(void**)($slot1+0x88), *(void**)($slot1+0x90), *(void**)($slot1+0x98)
    printf "F6 compar=%p search=%p n=%lu keylen=%lu\n", *(void**)($slot1+0xa0), *(void**)($slot1+0xa8), *(unsigned long*)($slot1+0xb0), *(unsigned long*)($slot1+0xb8)
    x/24gx $slot1+0x80
    rwatch -l *(unsigned long*)($slot1+0xa0)
    printf "F6 read-watchpoint armed on slot1+0xa0 (%p)\n", $slot1+0xa0
  end
  continue
end
run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
printf "STOP: rip=%p\n", $pc
info registers rip rdi rsi
bt 14
