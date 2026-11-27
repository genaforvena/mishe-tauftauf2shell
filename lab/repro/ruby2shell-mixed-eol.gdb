# W353: observe the single 0x53 byte at the next glibc chunk's size LSB
# for the mixed-parity shape on plain Ruby 3.2.11 (EOL branch).
# Source lines from ruby-3.2.11.tar.xz: xmalloc string.c:7336,
# case_map call :7341, used assignment :7352. With one leading 'a' and
# 27 sharp-s bytes the first case buffer has capa = 48, so
# current_buffer->space + capa == (char *)current_buffer + 72: the
# malloc usable size 72 puts that address on the successor's size word.
# Run:
#   gdb -q -batch -x lab/repro/ruby2shell-mixed-eol.gdb --args \
#     lab/build/plain/ruby-3.2.11-plain/bin/ruby \
#     lab/repro/ruby2shell-rung3-mixed.rb 27
set pagination off
set confirm off
break string.c:7341 if current_buffer->capa == 48
commands
  silent
  set $slot = (char *)current_buffer + 72
  printf "BEFORE buffer=%p capa=%lu target=%p old=", current_buffer, (unsigned long)current_buffer->capa, $slot
  x/1bx $slot
  continue
end
break string.c:7352 if $slot != 0
commands
  silent
  printf "AFTER used=%d target=%p new=", buffer_length_or_invalid, $slot
  x/1bx $slot
  disable $bpnum
  continue
end
run
quit
