set pagination off
set confirm off
set detach-on-fork on
set follow-fork-mode parent
set breakpoint pending on
break fork_watchdog_child
run -n -D -f lab/pgpool2shell/config/pgpool-w7.conf
set follow-fork-mode child
next
next
set $cnt = 0
break wd_json_data.c:136 if i == 128
break utils/json.c:1075 if value == (json_value *) 0x5555558c5ad8
commands
silent
set $cnt = $cnt + 1
printf "\n=== free_ex visit #%d to 0x5555558c5ad8 ===\n", $cnt
bt 3
continue
end
continue
printf "\n=== HIT config parser i=128 BEFORE store ===\n"
x/gx &config->backend_desc->backend_info[128].backend_port
next
printf "\n=== AFTER store ===\n"
x/gx &config->backend_desc->backend_info[128].backend_port
printf "\n=== continuing; visited-count so far=%d ===\n", $cnt
continue
printf "\n=== after free_ex, visited-count=%d ===\n", $cnt
bt 3
kill
quit
