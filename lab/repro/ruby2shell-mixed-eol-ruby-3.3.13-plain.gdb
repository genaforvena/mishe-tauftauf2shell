# W354: observe the single 0x53 byte at the next glibc chunk's size LSB
# for the mixed-parity shape on plain Ruby 3.3.13 (vulnerable branch).
# Source lines from ruby-3.3.13.tar.xz: case_map call string.c:7414,
# used assignment :7425 (xmalloc :7409). With one leading 'a' and
# 27 sharp-s bytes the first case buffer has capa = 48, so
# current_buffer->space + capa == (char *)current_buffer + 72, the
# successor's size word on stock glibc.
# Run:
#   gdb -q -batch -x lab/repro/ruby2shell-mixed-eol-ruby-3.3.13-plain.gdb --args \
#     lab/build/plain/ruby-3.3.13-plain/bin/ruby \
#     lab/repro/ruby2shell-rung3-mixed.rb 27
set pagination off
set confirm off
break string.c:7414 if current_buffer->capa == 48
commands
  silent
  set $slot = (char *)current_buffer + 72
  printf "BEFORE buffer=%p capa=%lu target=%p old=", current_buffer, (unsigned long)current_buffer->capa, $slot
  x/1bx $slot
  continue
end
break string.c:7425 if $slot != 0
commands
  silent
  printf "AFTER used=%d target=%p new=", buffer_length_or_invalid, $slot
  x/1bx $slot
  disable $bpnum
  continue
end
run
quit
