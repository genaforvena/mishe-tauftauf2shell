# Read-only observation of the stale append source pointer (no debugger writes).
set pagination off
set confirm off
break str_buf_cat4 if len == 64
run
printf "cat4-entry src=%p len=%ld\n", ptr, len
x/8xb ptr
set $p0 = ptr
break string.c:3447 if len == 64
continue
printf "memcpy src=%p entry=%p same=%d\n", ptr, $p0, ptr == $p0
x/8xb ptr
next
x/8xb sptr
continue
