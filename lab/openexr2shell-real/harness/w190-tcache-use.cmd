# W190 follow-up: after COPY2 poisons tcache[7]'s next word, watch the
# tcache entries[7] slot for the pop that would consume it.  Used only for a
# bounded negative/positive observation; not part of w190-tcache-check.sh.
set pagination off
set confirm off
break __memcpy_avx_unaligned_erms
continue
continue
finish
printf "POST-COPY2 head-word="
x/gx *(void**)((char*)tcache + 128 + 7*8)
watch *(void**)((char*)tcache + 128 + 7*8)
printf "POST-CONTINUE-STOP (check whether watchpoint 3 hit above)\n"
info registers rip
continue
printf "FINISHED\n"
quit
