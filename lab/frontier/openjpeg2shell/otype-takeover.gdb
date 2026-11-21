# Observe the TPsot=1 OOB store landing on a live Python object's ob_type.
# Local process only; gdb observes, it never writes memory.
# Invoke: gdb -q -batch -x otype-takeover.gdb --args python3 pillow-probe.py FILE
set pagination off
set breakpoint pending on
break j2k.c:5085
run
set $b = (char*)l_cstr_index->tile_index[p_j2k->m_current_tile_number].tp_index
printf "HIT0 tp=%u pos=%lld base=%p\n", l_cstr_index->tile_index[p_j2k->m_current_tile_number].current_tpsno, (long long)l_current_pos, $b
continue
set $b = (char*)l_cstr_index->tile_index[p_j2k->m_current_tile_number].tp_index
printf "HIT1 tp=%u pos=%lld BEFORE32=%016lx BEFORE40=%016lx WRITE32=%016lx WRITE40=%016lx\n", l_cstr_index->tile_index[p_j2k->m_current_tile_number].current_tpsno, (long long)l_current_pos, *(unsigned long*)($b+32), *(unsigned long*)($b+40), (unsigned long)l_current_pos, (unsigned long)(l_current_pos + p_j2k->m_specific_param.m_decoder.m_sot_length + 2)
until j2k.c:5091
printf "POST32=%016lx POST40=%016lx\n", *(unsigned long*)($b+32), *(unsigned long*)($b+40)
printf "PYTYPE &PyCode_Type=%p &PyUnicode_Type=%p &PyLong_Type=%p &PyType_Type=%p\n", &PyCode_Type, &PyUnicode_Type, &PyLong_Type, &PyType_Type
quit
