# Rung-4 probe (wake 5): after the F6 chosen-byte overwrite, watch the OTHER
# function-pointer field of the corrupted ngtcp2_ksl: `search` at slot1+0xa8.
# ngtcp2_ksl_insert():305 and ngtcp2_ksl_update_key():704 read ksl->search;
# wake 3 watched only `compar` at +0xa0. If trailing QUIC packets reach this
# pktns, gaptr_push() should read +0xa8 and the hardware watchpoint must fire.
set pagination off
set confirm off
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/harness/ksl-search.txt
set logging overwrite on
set logging redirect on
set logging enabled on
cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
set $seen = 0
set $ksl = 0
break wire_buf_consume
commands
  silent
  set $wb  = (unsigned long)$rdi
  set $len = (unsigned long)$rsi
  if $len == 1198 && $seen == 0
    set $seen = 1
    set $buf = *(unsigned long*)$wb
    set $slot1 = $buf + 6144
    set $ksl = $slot1 + 0x48
    printf "F6 buf=0x%lx slot1=0x%lx ksl=0x%lx compar=%p search=%p n=%lu\n", $buf, $slot1, $ksl, *(void**)($slot1+0xa0), *(void**)($slot1+0xa8), *(unsigned long*)($slot1+0xb0)
    rwatch -l *(unsigned long*)($slot1+0xa8)
    printf "W5 watchpoint armed on search slot1+0xa8=%p\n", $slot1+0xa8
  end
  continue
end
break ngtcp2_ksl_insert
commands
  silent
  if $ksl != 0 && $rdi == $ksl
    printf "DISPATCH HIT ksl_insert on corrupted ksl search=%p compar=%p\n", *(void**)($rdi+0x60), *(void**)($rdi+0x58)
  end
  continue
end
break ngtcp2_ksl_update_key
commands
  silent
  if $ksl != 0 && $rdi == $ksl
    printf "DISPATCH HIT ksl_update_key on corrupted ksl search=%p compar=%p\n", *(void**)($rdi+0x60), *(void**)($rdi+0x58)
  end
  continue
end
break ngtcp2_ksl_remove_hint
commands
  silent
  if $ksl != 0 && $rdi == $ksl
    printf "DISPATCH HIT ksl_remove_hint on corrupted ksl search=%p compar=%p\n", *(void**)($rdi+0x60), *(void**)($rdi+0x58)
  end
  continue
end
run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
printf "STOP: rip=%p\n", $pc
info registers rip rdi rsi
bt 14
