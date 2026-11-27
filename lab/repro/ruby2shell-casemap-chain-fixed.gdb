# W349 fixed-build variant: 3.4.13 shifted rb_str_casemap by 49 lines.
set pagination off
set confirm off
break string.c:7883
commands
silent
printf "ALLOC count=%lu capa=%lu\n", (unsigned long)buffer_count, (unsigned long)capa
continue
end
break string.c:7901
commands
silent
printf "USED count=%lu used=%d total=%d\n", (unsigned long)buffer_count, buffer_length_or_invalid, target_length
continue
end
run
quit
