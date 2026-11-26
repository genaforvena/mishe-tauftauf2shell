# Watch cumulative one-bit ORs from several codepoints into one heap word.
# Caller sets TOS_CODES (comma-separated hex codepoints) and runs gdb -batch
# -x this file against the plain 3.4.12 Ruby.
set pagination off
set confirm off
break regparse.c:4589 if *from >= 0x100
run lab/repro/ruby2shell-tos-multi.rb $TOS_CODES
printf "HIT code=%lu cc=%p\n", (unsigned long)*from, cc
set $target=(char *)cc+8+((int)(*from)/32)*4
printf "TARGET=%p DELTA=%ld\n", $target, $target-(char *)cc
delete 1
watch -l *(unsigned int *)$target
continue
continue
continue
quit
