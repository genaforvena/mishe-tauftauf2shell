# Capture the +6144 neighbour BEFORE the F6 OOB memcpy executes.
set pagination off
set confirm off
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/harness/ksl-prewrite.txt
set logging overwrite on
set logging redirect on
set logging enabled on
cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
set $seen = 0
break ../daemon/quic_conn.c:124 if $rdx == 1200
commands
  silent
  set $seen = 1
  set $dest = (unsigned long)$rdi
  set $buf = $dest - 6123
  set $slot1 = $buf + 6144
  printf "PREWRITE dest=%p buf=%p slot1=%p len=%lu\n", $dest, $buf, $slot1, $rdx
  x/48gx $slot1
  printf "gap compar=%p search=%p n=%lu\n", *(void**)($slot1+0xa0), *(void**)($slot1+0xa8), *(unsigned long*)($slot1+0xb0)
  printf "acktr compar=%p search=%p n=%lu\n", *(void**)($slot1+0x3e0), *(void**)($slot1+0x3e8), *(unsigned long*)($slot1+0x3f0)
  continue
end
run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
