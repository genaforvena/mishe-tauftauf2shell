set breakpoint pending on
set pagination off
break hpack.c:277
commands
silent
printf "STORE pos=%u c=0x%02x max=%u\n", ah->pos, c, wsi->a.context->max_http_header_data
continue
end
run
