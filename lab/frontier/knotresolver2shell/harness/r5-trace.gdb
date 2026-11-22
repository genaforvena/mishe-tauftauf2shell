# Dump the F6 OOB bytes at slot1 before any cleanup runs.
# Uses the same `run` path as the established oracle, so lib base is stable.
set pagination off
set confirm off
cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc

break wire_buf_consume
commands
  silent
  if $rsi == 1198
    set $wb = $rdi
    set $buf = *(unsigned long*)$wb
    set $slot1 = $buf + 6144
    printf "F6 buf=0x%lx slot1=0x%lx len=%lu\n", $buf, $slot1, $rsi
    printf "F6 extptrs:"
    x/4gx $slot1+0x100
    printf "F6 fake+0:"
    x/2bx $slot1+0x20
    printf "F6 fake+0xb8:"
    x/gx $slot1+0xd8
    printf "F6 fake+0x110:"
    x/gx $slot1+0x130
    printf "F6 fake+0x174:"
    x/wx $slot1+0x194
    printf "F6 fake+0x2d8:"
    x/wx $slot1+0x2f8
  end
  continue
end

run -n -c /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc/config /home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell/run/6.4.0-jemalloc
printf "STOP: rip=%p\n", $pc
