set pagination off
break wd_json_data.c:897
run 2 0x41414141 0x42424242
printf "i=%d node_id_set[0]=%p\n", i, node_id_set[0]
step
printf "buffer after write: %08x %08x\n", (*node_id_set)[0], (*node_id_set)[1]
quit
