# Inspect the OOB store at a chosen large TPsot in the pinned debug build.
# Invoke with: gdb -q -batch -ex 'set $want=188' -x large-tpsot.gdb --args \
#   python3 pillow-probe.py <generated.j2k>
set pagination off
set breakpoint pending on
break j2k.c:5085
run
set $s = l_cstr_index->tile_index[p_j2k->m_current_tile_number].current_tpsno
while $s != $want
  continue
  set $s = l_cstr_index->tile_index[p_j2k->m_current_tile_number].current_tpsno
end
set $b = (char*)l_cstr_index->tile_index[p_j2k->m_current_tile_number].tp_index
printf "SINK TP=%p TPSNO=%u POS=%lld\n", $b, $s, (long long)l_current_pos
printf "DST8_BYTEOFF=%ld OLD=%lx WRITE=%lx\n", $want*24+8, *(unsigned long*)($b+$want*24+8), (unsigned long)l_current_pos
printf "DST16_BYTEOFF=%ld OLD=%lx WRITE=%lx\n", $want*24+16, *(unsigned long*)($b+$want*24+16), (unsigned long)(l_current_pos + p_j2k->m_specific_param.m_decoder.m_sot_length + 2)
set $k=1
set $hits=0
while $k < 256
  set $v8 = *(unsigned long*)($b + $k*24 + 8)
  set $v16 = *(unsigned long*)($b + $k*24 + 16)
  if ($v8 >= 0x400000 && $v8 <= 0x700000) || ($v8 >= 0x7f0000000000 && $v8 <= 0x800000000000)
    printf "CAND off=%ld val=%lx\n", $k*24+8, $v8
    set $hits=$hits+1
  end
  if ($v16 >= 0x400000 && $v16 <= 0x700000) || ($v16 >= 0x7f0000000000 && $v16 <= 0x800000000000)
    printf "CAND off=%ld val=%lx\n", $k*24+16, $v16
    set $hits=$hits+1
  end
  set $k=$k+1
end
printf "CAND_HITS=%d\n", $hits
quit
