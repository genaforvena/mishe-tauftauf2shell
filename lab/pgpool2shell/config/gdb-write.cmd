set pagination off
set print pretty off
break wd_json_data.c:136
run 129 0x42424242
continue 128
print i
print &config->backend_desc->backend_info[i].backend_port
next
x/wx &config->backend_desc->backend_info[i].backend_port
print config->backend_desc->num_backends
quit
