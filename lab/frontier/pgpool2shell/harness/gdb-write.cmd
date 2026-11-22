set pagination off
break wd_json_data.c:858 if i == 1
run 2 0x41414141 0x42424242
printf "i=%d\n", i
printf "bad_index_ptr node_id_set[1] = %p\n", node_id_set[1]
printf "chosen value = 0x%08x\n", value->u.array.values[i]->u.integer
printf "--- target bytes before ---\n"
x/8bx node_id_set[1]
step
printf "--- target bytes after ---\n"
x/8bx node_id_set[1]
printf "--- store complete ---\n"
quit
