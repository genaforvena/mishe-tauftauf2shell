set disable-randomization on
start
break memcpy@plt if $rdx == 64
commands
silent
printf "DST=%p SRC=%p N=%lu\n", $rdi, $rsi, $rdx
continue
end
continue
