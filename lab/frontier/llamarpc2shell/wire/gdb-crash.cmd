set pagination off
set confirm off
run
printf "=== inferior stopped ===\n"
info registers rip
bt 6
kill
quit
