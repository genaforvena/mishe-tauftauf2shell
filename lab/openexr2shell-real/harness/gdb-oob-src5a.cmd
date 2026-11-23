set pagination off
set confirm off
break memcpy if $rdx == 4096
run cases/poc5a.exr
printf "SINK5A n=%lu dst=%p src=%p\n", $rdx, $rdi, $rsi
dump binary memory bin-vuln-plain/oob-src5a.bin $rsi $rsi+4096
quit
