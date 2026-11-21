# Local-only live-neighbour probe: does the OOB store land on a live object?
# Reuses the unsanitized pinned build; no source edits, no network.
set pagination off
set confirm off
break j2k.c:5086
run
continue
printf "H tile=%u tpsno=%u pos=%lld base0=%p base1=%p size56=0x%llx oob1=0x%llx\n", p_j2k->m_current_tile_number, l_current_tile_part, (long long)l_current_pos, l_cstr_index->tile_index[0].tp_index, l_cstr_index->tile_index[1].tp_index, *(unsigned long long*)((char*)l_cstr_index->tile_index[0].tp_index + 56), *(unsigned long long*)((char*)l_cstr_index->tile_index[0].tp_index + 32)
continue
printf "H tile=%u tpsno=%u pos=%lld base0=%p base1=%p size56=0x%llx oob1=0x%llx\n", p_j2k->m_current_tile_number, l_current_tile_part, (long long)l_current_pos, l_cstr_index->tile_index[0].tp_index, l_cstr_index->tile_index[1].tp_index, *(unsigned long long*)((char*)l_cstr_index->tile_index[0].tp_index + 56), *(unsigned long long*)((char*)l_cstr_index->tile_index[0].tp_index + 32)
continue
printf "H tile=%u tpsno=%u pos=%lld base0=%p base1=%p size56=0x%llx oob1=0x%llx\n", p_j2k->m_current_tile_number, l_current_tile_part, (long long)l_current_pos, l_cstr_index->tile_index[0].tp_index, l_cstr_index->tile_index[1].tp_index, *(unsigned long long*)((char*)l_cstr_index->tile_index[0].tp_index + 56), *(unsigned long long*)((char*)l_cstr_index->tile_index[0].tp_index + 32)
quit
