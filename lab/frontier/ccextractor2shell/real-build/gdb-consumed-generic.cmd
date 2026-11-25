set pagination off
set print pretty on
set confirm off
break ccx_gxf.c:1220
run
printf "after_write data_len=%lu buffer=%p boundary=%p\n", data->len, data->buffer, (unsigned char *)data->buffer + 2097272
x/12xb (unsigned char *)data->buffer + 2097272
tbreak process_m2v if length > 1000000
continue
printf "consumer_call data=%p length=%lu\n", data, length
finish
printf "program_consumed_got=%ld BUFSIZE=2097272 past=%ld\n", $rax, $rax - 2097272
bt 4
quit
