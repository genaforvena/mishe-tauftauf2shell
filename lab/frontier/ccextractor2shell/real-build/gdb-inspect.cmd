set pagination off
set confirm off
set print pretty on
break /tmp/ccx2shell-upstream-asan/src/lib_ccx/ccx_gxf.c:1220
run lab/frontier/ccextractor2shell/real-build/inputs/attack.gxf -o /tmp/ccx2shell-plain-attack.scc
printf "STOPPED data=%p buffer=%p data_len=%lu BUFSIZE=2097272\n", data, data->buffer, data->len
printf "bytes at nominal BUFSIZE boundary:\n"
x/32xb data->buffer + 2097272
printf "bytes 8 before computed write end (BUFSIZE+3976):\n"
x/8xb data->buffer + 2097272 + 3976 - 8
printf "first bytes of real buffer:\n"
x/16xb data->buffer
bt 5
quit
