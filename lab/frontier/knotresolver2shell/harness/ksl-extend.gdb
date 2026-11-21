# Extended-drift oracle: log allocation geometry at the final oversized frame.
set pagination off
set confirm off
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/harness/ksl-extend.txt
set logging overwrite on
set logging redirect on
set logging enabled on
set $seen = 0
set $n = 0
break wire_buf_consume
commands
  silent
  set $wb = (unsigned long)$rdi
  set $len = (unsigned long)$rsi
  set $n = $n + 1
  if $len > 1200
    set $buf = *(unsigned long*)$wb
    printf "FRAME n=%lu buf=%p len=%lu tracked=%lu\n", $n, $buf, $len, *(unsigned long*)($wb+8)
  end
  if $len == 1238 && $seen == 0
    set $seen = 1
    printf "=== F6 CANDIDATE ===\n"
    x/4gx $buf
    x/8gx $buf+6144
    x/4gx $buf+16384
    x/4gx $buf+32768
  end
  continue
end
run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
