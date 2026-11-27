# Fixed 3.4.13 control: breakpoint on the store line, which must not be hit
# because the index is revalidated after the to_int callback.
set pagination off
set confirm off
break string.c:6653
run
continue
