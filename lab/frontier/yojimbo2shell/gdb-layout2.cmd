set pagination off
set confirm off
set breakpoint pending on
break source/yojimbo_reliable_ordered_channel.cpp:716 if fragmentId == 2 && fragmentBytes == 500 && m_config.maxBlockSize == 1100
run 1795576058
printf "HIT blockData=%p\n", m_receiveBlock->blockData
printf "BEFORE-COPY words from blockData+1080 to +1560\n"
x/61gx m_receiveBlock->blockData+1080
printf "ASAN blockData\n"
call (void) __asan_describe_address(m_receiveBlock->blockData)
printf "ASAN blockData+1100\n"
call (void) __asan_describe_address(m_receiveBlock->blockData+1100)
printf "ASAN blockData+1500\n"
call (void) __asan_describe_address(m_receiveBlock->blockData+1500)
next
printf "AFTER-COPY words from blockData+1080 to +1560\n"
x/61gx m_receiveBlock->blockData+1080
quit
