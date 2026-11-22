set pagination off
set confirm off
set detach-on-fork on
set follow-fork-mode parent
set breakpoint pending on
break fork_watchdog_child
run -n -D -f lab/pgpool2shell/config/pgpool-w7.conf
printf "\n=== at fork_watchdog_child, following child ===\n"
set follow-fork-mode child
next
next
break wd_json_data.c:136 if i == 128
continue
printf "\n=== ALIAS WIRE HIT i=128 BEFORE store ===\n"
print i
print config->backend_desc
print &config->backend_desc->backend_info[128].backend_port
print root
print root->u.object.length
set $dest = (char *) &config->backend_desc->backend_info[128].backend_port
set $i = 0
while $i < root->u.object.length
  printf "entry %d name=%s value=%p value_field_addr=%p%s\n", $i, root->u.object.values[$i].name, root->u.object.values[$i].value, &root->u.object.values[$i].value, ((char *)&root->u.object.values[$i].value == $dest) ? "  <== OOB DEST" : ""
  set $i = $i + 1
end
printf "\n=== bytes at destination BEFORE store ===\n"
x/8gx $dest - 32
printf "\n=== stepping over line 136 ===\n"
next
printf "\n=== bytes at destination AFTER store ===\n"
x/8gx $dest - 32
printf "\n=== continuing to fault ===\n"
continue
bt 6
