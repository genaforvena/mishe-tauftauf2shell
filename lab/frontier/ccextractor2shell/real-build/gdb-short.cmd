set pagination off
set print pretty on
set confirm off
break ccx_gxf.c:1220
run
printf "SHORT after_parse data_len=%lu buffer=%p boundary=%p\n", data->len, data->buffer, (unsigned char *)data->buffer + 2097272
x/8xb (unsigned char *)data->buffer
break general_loop.c:1041
continue
printf "SHORT memmove got=%ld data_len=%ld move_len=%ld src=%p dst=%p\n", got, data_node->len, (long)(data_node->len - got), data_node->buffer + got, data_node->buffer
bt 4
quit
