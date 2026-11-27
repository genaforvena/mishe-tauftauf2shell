set pagination off
set confirm off
set environment W331C_N 4096
set environment W331C_RECLAIM 1
break rb_memsearch if $rsi == 4096
commands
  silent
  printf "MS ptr=%p len=%ld\n", $rdi, $rsi
  x/32bx $rdi
  continue
end
run lab/repro/ruby2shell-eachline-stale-chosen.rb
quit
