set pagination off
break wd_json_data.c:858
run 2 0x41414141 0x42424242
printf "i=%d node_id_set=%p node_id_set[0]=%p node_id_set[1]=%p\n", i, node_id_set, node_id_set[0], node_id_set[1]
printf "chosen_value=%08x  write_addr=%p\n", value->u.array.values[i]->u.integer, node_id_set[i]
x/4gx node_id_set
printf "--- caller frame ---\n"
frame 1
info locals
quit
