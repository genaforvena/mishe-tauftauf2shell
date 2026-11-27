# W351: 3.3.14 patched build; rb_str_casemap xmalloc at string.c:7433,
# used assignment at string.c:7451 (source from ruby-3.3.14.tar.xz).
set pagination off
set confirm off
break string.c:7433
commands
silent
printf "ALLOC count=%lu capa=%lu\n", (unsigned long)buffer_count, (unsigned long)capa
continue
end
break string.c:7451
commands
silent
printf "USED count=%lu used=%d total=%d\n", (unsigned long)buffer_count, buffer_length_or_invalid, target_length
continue
end
run
quit
