# Debugger READ of the chosen bytes only; no register or memory write.
# Run from the repository root with -x, on the vulnerable plain 3.4.12 build.
set pagination off
set confirm off
set print elements 0
break memmove if $rdx == 3 && *(unsigned int*)$rsi == 0x004a515a
run lab/repro/ruby2shell-backref-stale-equal.rb attack:700
printf "=== CHOSEN memmove(dest=%p src=%p size=%ld) ===\n", $rdi, $rsi, $rdx
x/12cb $rdi-4
finish
printf "=== AFTER chosen memmove ===\n"
x/12cb $rdi-4
quit
