# Read-only observation of the chosen OOB bytes after the stale-length memcpy
# (no debugger writes).  Run with W330B_ACTION=arg W330B_LEN=4096
# W330B_ARG=8192 W330B_BYTE=90 against the vulnerable plain build.
set pagination off
set confirm off
break string.c:3841
run
set $r = (struct RString *)str
printf "post-memcpy ptr=%p len=%ld sptr=%p delta=%ld\n", $r->as.heap.ptr, $r->len, sptr, sptr - $r->as.heap.ptr
x/16xb $r->as.heap.ptr + 4088
x/16xb $r->as.heap.ptr + 8184
continue
