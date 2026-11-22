set pagination off
set confirm off
set breakpoint pending on
break wd_json_data.c:136 if i == 128
run 129 0x42424242
printf "\n=== ALIAS HIT: i=128 before port store ===\n"
print i
print sizeof(BackendDesc)
print config->backend_desc
print &config->backend_desc->backend_info[128].backend_port
print root
set $bv = json_get_value_for_key(root, "backend_desc")
print $bv
print $bv->u.array.length
print $bv->u.array.values
set $idx = ((char *) &config->backend_desc->backend_info[128].backend_port - (char *) $bv->u.array.values) / 8
print $idx
printf "\n=== values[] window BEFORE store ===\n"
x/16gx $bv->u.array.values + $idx - 6
set $old = $bv->u.array.values[$idx]
print $old
printf "\n=== stepping over line 136 (the port store) ===\n"
next
printf "\n=== values[] window AFTER store ===\n"
x/16gx $bv->u.array.values + $idx - 6
print $bv->u.array.values[$idx]
print $old
printf "\n=== continuing to fault ===\n"
continue
printf "\n=== stop reason / backtrace ===\n"
bt 8
