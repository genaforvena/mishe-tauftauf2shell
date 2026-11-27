# W361: read the successor chunk's size LSB around the fold-byte write.
# Mixed driver N=27 gives capa=48, malloc request R=capa+24=72; on stock
# glibc that is a 0x50 chunk whose successor starts at buffer+64, so
# buffer+72 is the successor's size LSB. downcase(:fold) writes 0x73
# there. Source lines for 3.4.12: case_map call string.c:7839,
# used assignment :7850.
# Run:
#   gdb -q -batch -x lab/repro/ruby2shell-mixed-fold-size.gdb --args \
#     lab/build/plain/ruby-3.4.12-plain/bin/ruby \
#     lab/repro/ruby2shell-rung3-mixed-fold.rb 27 fold
set pagination off
set confirm off
set $slot = 0
set $seen = 0
break string.c:7839 if current_buffer != 0 && current_buffer->capa == 48
commands
  silent
  set $slot = (char *)current_buffer + 72
  set $seen = 1
  printf "BEFORE header(prev,size)="
  x/2gx (char *)current_buffer - 16
  printf "BEFORE buffer=%p capa=%lu slot=%p prev7=", current_buffer, (unsigned long)current_buffer->capa, $slot
  x/1bx $slot - 1
  printf "BEFORE sizeLSB="
  x/1bx $slot
  printf "BEFORE sizebyte1="
  x/1bx $slot + 1
  continue
end
break string.c:7850 if $seen == 1
commands
  silent
  printf "AFTER used=%d prev7=", buffer_length_or_invalid
  x/1bx $slot - 1
  printf "AFTER sizeLSB="
  x/1bx $slot
  printf "AFTER sizebyte1="
  x/1bx $slot + 1
  disable $bpnum
  set $seen = 0
  continue
end
run
quit
