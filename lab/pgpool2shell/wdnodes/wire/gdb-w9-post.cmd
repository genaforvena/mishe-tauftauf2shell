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
printf "\n=== setting post-parse breakpoint at watchdog.c:4476 ===\n"
break watchdog.c:4476
continue
printf "\n=== HIT after get_pool_config_from_json returned ===\n"
print standby_config
print standby_config->wd_nodes.num_wd
print standby_config->trusted_servers
x/gx &standby_config->trusted_servers
print standby_config->wd_nodes.wd_node_info[128].wd_port
print standby_config->wd_nodes.wd_node_info[128].pgpool_port
print standby_config->wd_nodes.wd_node_info[128].hostname
bt 5
printf "=== end readback ===\n"
