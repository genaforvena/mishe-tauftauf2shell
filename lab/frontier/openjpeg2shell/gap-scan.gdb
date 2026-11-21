# Enumerate live Python object headers in the 24-byte-strided OOB region.
# gdb observes only; it never writes memory. Invoke with a codestream that
# reaches the pinned j2k.c:5085 sink. Usage:
#   gdb -q -batch -x gap-scan.gdb --args python3 pillow-probe.py FILE
set pagination off
set breakpoint pending on
break j2k.c:5085
run
set $base = (char*)l_cstr_index->tile_index[p_j2k->m_current_tile_number].tp_index
printf "BASE=%p\n", $base
set $off = 0
while $off < 65536
  set $r = *(unsigned long*)($base+$off)
  set $t = *(unsigned long*)($base+$off+8)
  if $r > 0 && $r < 128 && $t > 0xa00000 && $t < 0xa60000
    printf "OBJ off=%ld mod24=%ld refcnt=%ld type=%lx\n", $off, $off%24, $r, $t
  end
  set $off = $off + 8
end
quit
