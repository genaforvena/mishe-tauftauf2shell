# Trace whether the neighbour ksl is the one used after the F6 overwrite.
set pagination off
set confirm off
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/harness/ksl-trace.txt
set logging overwrite on
set logging redirect on
set logging enabled on
cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
set $slot1 = 0
set $seen = 0
break ngtcp2_ksl_insert if $slot1 != 0
commands
  silent
  printf "POST-F6 KSL-INSERT ksl=%p compar=%p target=%p\n", $rdi, *(void**)($rdi+0x58), $slot1+0x48
  continue
end
break wire_buf_consume
commands
  silent
  set $wb = (unsigned long)$rdi
  set $len = (unsigned long)$rsi
  if $len == 1198 && $seen == 0
    set $seen = 1
    set $slot1 = *(unsigned long*)$wb + 6144
    printf "F6 slot1=%p gaptr-ksl-target=%p compar=%p\n", $slot1, $slot1+0x48, *(void**)($slot1+0xa0)
  end
  continue
end
run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
