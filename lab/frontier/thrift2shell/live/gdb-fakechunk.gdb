# ASLR-on replay of the forged-chunk free limb. $want is set by run-fakechunk.sh.
# Dumps are raw evidence; only the normalizer's output is committed.
set pagination off
set confirm off
set print pretty off
set breakpoint pending on
set disable-randomization off
set $rb = 0
set $n = 0
set $matched = 0
set $matchn = 0
break THeaderTransport.cpp:301
commands 1
 silent
 set $rb = rBuf_.get()
 printf "PRE RBUF=%p SZ=%u\n", $rb, sz
 continue
end
break __libc_free
commands 2
 silent
 if $rdi != 0 && $rb != 0
  set $n = $n + 1
  if ($rdi & 0xffff) == $want && $matched == 0
   set $matched = 1
   set $matchn = $n
   printf "WANTFREE n=%d mem=%p rbuf=%p\n", $n, $rdi, $rb
   dump binary memory results/fakechunk-before.bin $rb $rb+1024
  end
  if $matched == 1 && $n == $matchn + 1
   dump binary memory results/fakechunk-after.bin $rb $rb+1024
  end
 end
 continue
end
run
printf "END n=%d matched=%d\n", $n, $matched
