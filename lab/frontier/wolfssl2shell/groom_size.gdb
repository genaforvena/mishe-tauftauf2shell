set pagination off
set confirm off
set print thread-events off
set print elements 0
printf "FACT FLUSH head=%p rn=%p next=%p list=%p\n", ssl->dtls13Rtx.seenRecords, rn, rn->next, list
printf "FACT SIZEFIELD addr=%p val=%p\n", (char*)rn-8, *(void**)((char*)rn-8)
printf "FACT CHUNKQWORDS\n"
x/4gx (char*)rn-16
continue
printf "FACT POST_INFERIOR\n"
bt 6
