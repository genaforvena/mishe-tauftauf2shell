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
printf "\n=== in watchdog child, setting config-parser breakpoint ===\n"
break wd_json_data.c:138 if i == 128
commands
silent
printf "\n=== HIT config parser i=128 ===\n"
print i
print config->backend_desc->num_backends
print &config->backend_desc->backend_info[i].backend_port
x/wx &config->backend_desc->backend_info[i].backend_port
bt 8
printf "=== continuing to fault ===\n"
continue
end
continue
