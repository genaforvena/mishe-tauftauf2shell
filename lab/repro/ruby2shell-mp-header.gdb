# Observe the next-heap-chunk size word corrupted by the wire-only
# Rack::MethodOverride `_method` overflow (CVE-2026-132825), plain 3.4.12.
#
# Launch a loopback Sinatra server under gdb and send one mixed27 POST from a
# second shell:
#   gdb -batch -x lab/repro/ruby2shell-mp-header.gdb --args \
#     lab/build/plain/ruby-3.4.12-plain/bin/ruby \
#     lab/repro/ruby2shell-stock-baseline.ru
#   python3 lab/repro/ruby2shell-mp-method-21.py PORT mixed27
#
# `capa == 48` selects the wire mixed27 part (a + 27 x 0xDF). The casemap
# buffer's malloc usable size is 72, so space+capa == buffer+72 is the next
# chunk's SIZE word. The single 0x53 byte written there changes the size
# class (0x45/0x35/0x155 -> 0x53) and sets IS_MMAPPED, keeping PREV_INUSE.
# Evidence is gitignored under lab/build/evidence/mp-method-21/.
set pagination off
set $np = 0
set logging file lab/build/evidence/mp-method-21/gdb-mp-header.log
set logging overwrite on
set logging enabled on

break abort
commands
  printf "=== ABORT ===\n"
  bt 30
  quit
end

break string.c:7839 if current_buffer->capa == 48
commands
  silent
  set $np = (char *)current_buffer + 72
  printf "=== BEFORE buffer=%p next_size_at=%p ===\n", current_buffer, $np
  x/2gx $np
  continue
end

break string.c:7856 if $np != 0
commands
  silent
  printf "=== AFTER case_map ===\n"
  x/2gx $np
  disable $bpnum
  continue
end
run
