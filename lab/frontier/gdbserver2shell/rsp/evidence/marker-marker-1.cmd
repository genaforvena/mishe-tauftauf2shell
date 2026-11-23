set pagination off
set confirm off
set follow-fork-mode parent
run
printf "\n=== AFTER_RUN ===\n"
bt 8
info registers rip rax rdi
