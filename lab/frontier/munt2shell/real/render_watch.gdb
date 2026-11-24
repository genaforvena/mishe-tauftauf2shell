# Watch a chosen first-input byte at streamBuffer+38000 after the real
# 40001-byte memcpy, through the later real parseStream dispatch and render.
set pagination off
set confirm off
set print thread-events off
break memcpy if $rdx == 40001
run render-attack
set $dst = (char *)$rdi
printf "OBS memcpy_dst=%p src=%p len=%lu\n", $dst, (void *)$rsi, (unsigned long)$rdx
finish
set $oob = $dst + 38000
printf "OBS watch_addr=%p first_byte=%02x\n", $oob, *(unsigned char *)$oob
watch -l *(unsigned char *)$oob
commands
silent
printf "OBS watch_hit_pc=%s\n", ...
bt 3
continue
end
printf "OBS armed_before_later_input\n"
continue
quit
