# W357: read the bytes around the k=3 case_map write slot (N=27, capa=50).
# slot = (char *)current_buffer + 24 + capa == current_buffer + 74.
# A 74-byte request gives a 0x60 chunk on stock glibc: the successor chunk
# starts at current_buffer + 80, so +74 is six bytes before that boundary.
# Source: case_map call string.c:7839, used assignment :7850 (3.4.12).
# Run:
#   gdb -q -batch -x lab/repro/ruby2shell-mixed3-slot.gdb --args \
#     lab/build/plain/ruby-3.4.12-plain/bin/ruby \
#     lab/repro/ruby2shell-rung3-mixed3.rb 27
set pagination off
set confirm off
set $slot = 0
set $seen = 0
break string.c:7839 if current_buffer != 0 && current_buffer->capa == 50
commands
  silent
  set $slot = (char *)current_buffer + 74
  set $seen = 1
  printf "BEFORE buffer=%p capa=%lu slot=%p ", current_buffer, (unsigned long)current_buffer->capa, $slot
  x/24bx $slot - 16
  continue
end
break string.c:7850 if $seen == 1
commands
  silent
  printf "AFTER used=%d ", buffer_length_or_invalid
  x/24bx $slot - 16
  disable $bpnum
  set $seen = 0
  continue
end
run
quit
