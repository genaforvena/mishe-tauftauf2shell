# Local-only low-bit grooming probe for OSV-2025-219.
# Breakpoints: the real OOB stores, then the teardown free() of m_mct_records
# whose chunk-size word those stores overwrote. Invoked by groom.sh with
# GROOM_IN pointing at a padded codestream. No source edits, no network.
set pagination off
set confirm off
break j2k.c:5086
break free
disable 2
run
printf "SINK1 tile=%u tpsno=%u pos=%lld base0=%p\n", p_j2k->m_current_tile_number, l_current_tile_part, (long long)l_current_pos, l_cstr_index->tile_index[0].tp_index
set $t0 = l_cstr_index->tile_index[0].tp_index
set $bad = $t0 + 64
continue
printf "SINK2 tile=%u tpsno=%u pos=%lld size56=0x%llx prev48=0x%llx\n", p_j2k->m_current_tile_number, l_current_tile_part, (long long)l_current_pos, *(unsigned long long*)($t0 + 56), *(unsigned long long*)($t0 + 48)
continue
printf "SINK3 tile=%u tpsno=%u pos=%lld size56=0x%llx prev48=0x%llx\n", p_j2k->m_current_tile_number, l_current_tile_part, (long long)l_current_pos, *(unsigned long long*)($t0 + 56), *(unsigned long long*)($t0 + 48)
enable 2
continue
printf "FREE ptr=%p sizeword=0x%llx prevsize=0x%llx\n", $rdi, *(unsigned long long*)($rdi - 8), *(unsigned long long*)($rdi - 16)
info proc mappings
continue
printf "EXITED\n"
quit
