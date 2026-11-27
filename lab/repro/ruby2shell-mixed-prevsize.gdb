# W356: read the bytes around the mixed-parity write slot (N=35, capa=56)
# before and after rb_str_casemap on plain Ruby 3.4.12. The write address is
# current_buffer->space + capa == (char *)current_buffer + 80.
# An 80-byte request gives a 0x60 chunk on stock glibc: slot +80 is the
# successor chunk's prev_size LSB and +88 its size LSB; slot -8 is in-bounds.
# Source: case_map call string.c:7839, used assignment :7850.
# Run:
#   gdb -q -batch -x lab/repro/ruby2shell-mixed-prevsize.gdb --args \
#     lab/build/plain/ruby-3.4.12-plain/bin/ruby \
#     lab/repro/ruby2shell-rung3-mixed.rb 35
set pagination off
set confirm off
set $slot = 0
set $seen = 0
break string.c:7839 if current_buffer != 0 && current_buffer->capa == 56
commands
  silent
  set $slot = (char *)current_buffer + 80
  set $seen = 1
  printf "BEFORE buffer=%p capa=%lu slot=%p inbounds=%p ", current_buffer, (unsigned long)current_buffer->capa, $slot, $slot - 8
  x/1bx $slot - 8
  printf "BEFORE slot old="
  x/1bx $slot
  printf "BEFORE next old="
  x/1bx $slot + 8
  continue
end
break string.c:7850 if $seen == 1
commands
  silent
  printf "AFTER used=%d inbounds=", buffer_length_or_invalid
  x/1bx $slot - 8
  printf "AFTER slot new="
  x/1bx $slot
  printf "AFTER next new="
  x/1bx $slot + 8
  disable $bpnum
  set $seen = 0
  continue
end
run
quit
