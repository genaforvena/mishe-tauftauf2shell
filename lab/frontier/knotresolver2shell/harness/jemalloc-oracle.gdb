# Observe the real jemalloc neighbour of pers_inbuf on THIS host.
# Runs kresd under gdb (ptrace_scope=1 requires gdb to be the parent).
# No ASLR change: the breakpoint is symbolic, addresses are read at runtime.
set pagination off
set confirm off
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/harness/jemalloc-oracle.txt
cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
set logging overwrite on
set logging redirect on
set logging enabled on
set $seen = 0
break wire_buf_consume
commands
  silent
  set $wb  = (unsigned long)$rdi
  set $len = (unsigned long)$rsi
  set $siz = *(unsigned long*)($wb + 8)
  if $len == 1438 && $siz == 6960 && $seen == 0
    set $seen = 1
    printf "ORACLE: buf=0x%lx slot1=0x%lx len=%lu size=%lu\n", *(unsigned long*)$wb, *(unsigned long*)$wb + 6144, $len, $siz
    printf "ORACLE: --- own buffer first 0x80 bytes ---\n"
    x/16gx *(unsigned long*)$wb
    printf "ORACLE: --- slot1 first 0x300 bytes (reference target offsets 0xb8/0x110/0x174) ---\n"
    x/96gx *(unsigned long*)$wb + 6144
    printf "ORACLE: --- jemalloc chunk header just before buf (0x60 bytes) ---\n"
    x/12gx *(unsigned long*)$wb - 0x60
    info proc mappings
  end
  continue
end
run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
