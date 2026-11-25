set pagination off
set confirm off
set breakpoint pending on
break source/yojimbo_reliable_ordered_channel.cpp:716 if fragmentId == 2 && fragmentBytes == 500 && m_config.maxBlockSize == 1100
run 1795576058
next
continue
frame 0
printf "FAULT INSTRUCTION: "
x/i $pc
info registers rax rbx rcx rdx rsi rdi r8 r9
printf "SYM at 0x5555556c6268: "
info symbol 0x5555556c6268
quit
