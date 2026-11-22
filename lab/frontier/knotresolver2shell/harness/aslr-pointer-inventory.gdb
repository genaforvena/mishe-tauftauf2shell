# ASLR-ON one-shot inventory of the live gnutls session and its real
# extension-priv object, taken at the same pre-F6 wire_buf_consume hit as
# gnutls-owner-aslr.gdb.  Purpose: test whether a 2-byte low-order patch of
# an already-live pointer could reach system() or a heap command string
# without knowing ASLR high bits.  Loopback only; host sysctl untouched.
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
      set $priv = *(unsigned long*)($slot1+0x100)
      printf "INV_PRE_F6 buf=0x%lx slot1=0x%lx priv=0x%lx\n", $buf, $slot1, $priv
      printf "INV_SYSTEM=%p\n", &system
      x/128gx $slot1
      x/128gx $priv
      info proc mappings
      quit
    end
  end
  continue
end
run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
printf "INV_NO_HIT rip=%p\n", $pc
