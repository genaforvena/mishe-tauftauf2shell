set pagination off
set confirm off
set breakpoint pending on
break source/yojimbo_reliable_ordered_channel.cpp:716 if fragmentId == 2 && fragmentBytes == 500 && m_config.maxBlockSize == 1100
run 1795576058
set $bd = m_receiveBlock->blockData
printf "blockData=%p\n", $bd
next
printf "POST value at +1200 = %p\n", *(void**)($bd+1200)
rwatch *(unsigned long long*)($bd+1200)
printf "CONTINUING TO READ WATCHPOINT\n"
continue
printf "WATCHPOINT HIT PC\n"
bt 8
quit
