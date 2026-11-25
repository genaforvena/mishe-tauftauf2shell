set pagination off
set confirm off
set breakpoint pending on
break source/yojimbo_reliable_ordered_channel.cpp:716 if fragmentId == 2 && fragmentBytes == 500 && m_config.maxBlockSize == 1100
run 1795576058
next
continue
frame 0
printf "connection=%p\n", this
printf "numChannels=%d\n", m_connectionConfig.numChannels
printf "channel0=%p channel1=%p\n", m_channel[0], m_channel[1]
printf "vtable0=%p vtable1=%p\n", *(void**)m_channel[0], *(void**)m_channel[1]
quit
