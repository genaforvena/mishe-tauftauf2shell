# W198: scan the tail of the W197 COPY2 window at the indirect call site.
# ASLR OFF, so the fixed-point destination and its copy end are stable.
set pagination off
set confirm off
set disable-randomization on
break opaque.c:79
run
printf "=== TAIL_WORDS ===\n"
x/18gx 0x555555828c80
quit
