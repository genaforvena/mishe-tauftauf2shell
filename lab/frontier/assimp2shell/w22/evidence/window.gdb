set disable-randomization on
start
break memcpy@plt if $rdx == 64 && $rdi == 0x7fffffffc534
continue
printf "DST=%p SRC=%p N=%lu\n", $rdi, $rsi, $rdx
x/64bx $rdi
x/16bx $rsi
