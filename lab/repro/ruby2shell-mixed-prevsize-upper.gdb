# W359: read the successor prev_size bytes around the mixed-parity write
# slot on plain Ruby 3.4.12 with N=23 (capa=44). Overflow requires even
# capa; the malloc request is R=capa+24=68, stock glibc uses a 0x50 chunk
# (C=80), so the successor starts at buffer+64 and its prev_size spans
# buffer+64 .. buffer+71. slot = buffer+68 = successor prev_size byte 4.
# Source breakpoints: case_map call string.c:7839, used assignment :7850.
# Run:
#   gdb -q -batch -x lab/repro/ruby2shell-mixed-prevsize-upper.gdb --args \
#     lab/build/plain/ruby-3.4.12-plain/bin/ruby \
#     lab/repro/ruby2shell-rung3-mixed.rb 23
set pagination off
set confirm off
set $slot = 0
set $seen = 0
break string.c:7839 if current_buffer != 0 && current_buffer->capa == 44
commands
  silent
  set $slot = (char *)current_buffer + 68
  set $seen = 1
  printf "BEFORE header(prev,size)="
  x/2gx (char *)current_buffer - 16
  printf "BEFORE buffer=%p capa=%lu slot=%p prev0=", current_buffer, (unsigned long)current_buffer->capa, $slot
  x/1bx $slot - 4
  printf "BEFORE slot(prev4)="
  x/1bx $slot
  printf "BEFORE prev5="
  x/1bx $slot + 1
  printf "BEFORE sizeLSB="
  x/1bx $slot + 4
  continue
end
break string.c:7850 if $seen == 1
commands
  silent
  printf "AFTER used=%d prev0=", buffer_length_or_invalid
  x/1bx $slot - 4
  printf "AFTER slot(prev4)="
  x/1bx $slot
  printf "AFTER prev5="
  x/1bx $slot + 1
  printf "AFTER sizeLSB="
  x/1bx $slot + 4
  disable $bpnum
  set $seen = 0
  continue
end
run
quit
