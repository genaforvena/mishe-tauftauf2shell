# Sample eight-byte windows across the forged tail after the real oversized
# memcpy completes. A hit means a process instruction touched chosen bytes.
set pagination off
set confirm off
set print thread-events off
break memcpy if $rdx == 40001
run default-attack
set $dst = (char *)$rdi
printf "OBS memcpy_dst=%p len=%lu\n", $dst, (unsigned long)$rdx
finish
set $i = 0
while $i < 4
  set $off = 32768 + $i * 2400
  set $addr = $dst + $off
  printf "OBS watch_offset=%lu addr=%p first=%02x\n", (unsigned long)$off, $addr, *(unsigned char *)$addr
  watch -l *(unsigned long long *)$addr
  set $i = $i + 1
end
commands 2
silent
printf "OBS HIT wp2 pc=%s\n", ...
bt 3
continue
end
commands 3
silent
printf "OBS HIT wp3 pc=%s\n", ...
bt 3
continue
end
commands 4
silent
printf "OBS HIT wp4 pc=%s\n", ...
bt 3
continue
end
commands 5
silent
printf "OBS HIT wp5 pc=%s\n", ...
bt 3
continue
end
continue
printf "OBS end_of_run\n"
quit
