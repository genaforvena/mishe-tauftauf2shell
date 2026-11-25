set pagination off
set confirm off
set breakpoint pending on
break source/yojimbo_reliable_ordered_channel.cpp:716 if fragmentId == 2 && fragmentBytes == 500 && m_config.maxBlockSize == 1100
run 1795576058
next
continue
frame 0
printf "CRASH PC %p\n", $pc
printf "si_addr %p\n", $_siginfo._sifields._sigfault.si_addr
printf "connection=%p\n", this
printf "numChannels=%d\n", m_numChannels
printf "channel[0]=%p channel[1]=%p\n", m_channel[0], m_channel[1]
printf "connection context=%p\n", m_context
x/16gx this
quit
