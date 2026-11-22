set pagination off
set confirm off
set detach-on-fork on
set follow-fork-mode parent
set breakpoint pending on
break fork_watchdog_child
run -n -D -f lab/pgpool2shell/wire/pgpool-vuln.conf
printf "\n=== at fork_watchdog_child, following child ===\n"
set follow-fork-mode child
next
next
printf "\n=== in O2 watchdog child, setting parser breakpoint ===\n"
break wd_json_data.c:858
commands
silent
printf "\n=== HIT wd_json_data.c:858 (O2) ===\n"
print i
print node_count
print node_id_set
print *node_id_set
print node_id_set[1]
printf "=== caller frame ===\n"
frame 1
info locals
info registers rbp rsp
printf "=== stack window around rbp ===\n"
x/12gx $rbp-0x60
printf "=== backtrace ===\n"
bt 8
printf "=== continuing to fault ===\n"
continue
end
continue
