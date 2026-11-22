set pagination off
set confirm off
set detach-on-fork on
set follow-fork-mode parent
set breakpoint pending on
break fork_watchdog_child
run -n -D -f lab/pgpool2shell/wdnodes/wire/pgpool-w9.conf
printf "\n=== at fork_watchdog_child, following child ===\n"
set follow-fork-mode child
next
next
printf "\n=== in watchdog child, setting wd_nodes OOB breakpoint ===\n"
break wd_json_data.c:202 if i == 128
commands
silent
printf "\n=== HIT wd_nodes strncpy i=128 BEFORE ===\n"
print i
print config->wd_nodes.num_wd
print config->trusted_servers
x/gx &config->trusted_servers
next
printf "\n=== AFTER strncpy ===\n"
print config->trusted_servers
x/gx &config->trusted_servers
print config->wd_nodes.wd_node_info[128].wd_port
print config->wd_nodes.wd_node_info[128].pgpool_port
bt 6
printf "=== continuing ===\n"
continue
end
continue
