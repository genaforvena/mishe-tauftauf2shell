set pagination off
set confirm off
set breakpoint pending on
break source/yojimbo_reliable_ordered_channel.cpp:716 if fragmentId == 2 && fragmentBytes == 500 && m_config.maxBlockSize == 1100
run 1795576058
printf "HIT blockData=%p channel=%p receiveBlock=%p\n", m_receiveBlock->blockData, this, m_receiveBlock
printf "CONFIG maxBlockSize=%d fragmentSize=%d\n", m_config.maxBlockSize, m_config.blockFragmentSize
next
printf "POST-COPY: words from blockData+1080 to +1560\n"
x/61gx m_receiveBlock->blockData+1080
printf "FRAMES\n"
bt 5
printf "SEND/RECV allocator=%p\n", m_allocator
quit
