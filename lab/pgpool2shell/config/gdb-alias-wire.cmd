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
printf "\n=== alias breakpoint at config-parser port store ===\n"
break wd_json_data.c:136 if i == 128
continue
printf "\n=== ALIAS WIRE HIT i=128 BEFORE store ===\n"
print i
print config->backend_desc
print &config->backend_desc->backend_info[128].backend_port
print root
x/20gx &config->backend_desc->backend_info[128].backend_port - 64
printf "\n=== stepping over line 136 ===\n"
next
printf "\n=== AFTER store ===\n"
x/20gx &config->backend_desc->backend_info[128].backend_port - 64
printf "\n=== continuing to fault ===\n"
continue
printf "\n=== stop reason ===\n"
bt 6
