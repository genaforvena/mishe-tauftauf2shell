set pagination off
set confirm off
break memcpy if $rdx == 4096
run cases/poc.exr
printf "SINK n=%lu dst=%p src=%p\n", $rdx, $rdi, $rsi
dump binary memory bin-vuln-plain/oob-src.bin $rsi $rsi+4096
dump binary memory bin-vuln-plain/oob-dst.bin $rdi $rdi+4096
quit
