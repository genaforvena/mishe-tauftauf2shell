# Read-only observation of the stale String#setbyte store (no debugger writes).
set pagination off
set confirm off
break string.c:6609
run
printf "pos=%ld len=%ld ptr=%p\n", pos, len, ptr
x/3xb ptr
next
x/3xb ptr
continue
