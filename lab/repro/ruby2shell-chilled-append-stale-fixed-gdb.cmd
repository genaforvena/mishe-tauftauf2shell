# Fixed 3.4.13: str_modify_keep_cr runs before the RHS pointer is read, so the
# 4096-byte append source must already be the replacement buffer. Read only.
set pagination off
set confirm off
break str_buf_cat4 if len == 4096
run
printf "cat4-entry src=%p len=%ld\n", ptr, len
x/8xb ptr
continue
