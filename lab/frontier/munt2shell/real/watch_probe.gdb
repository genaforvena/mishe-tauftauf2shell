# Watch the first byte past the real new Bit8u[32768] allocation after the
# oversized memcpy completes. Any later read or write of that byte stops here.
set pagination off
set confirm off
set print thread-events off
break memcpy if $rdx == 40001
run default-attack
set $dst = (char *)$rdi
printf "OBS memcpy_dst=%p src=%p len=%lu\n", $dst, (void *)$rsi, (unsigned long)$rdx
finish
set $oob = $dst + 32768
printf "OBS oob_addr=%p first_byte=%02x\n", $oob, *(unsigned char *)$oob
watch -l *(unsigned char *)$oob
commands
silent
printf "OBS watch_hit_frame0=%s\n", ...
bt 3
continue
end
continue
printf "OBS end_of_run\n"
quit
