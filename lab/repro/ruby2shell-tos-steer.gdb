# Observe the attacker-chosen one-bit write in the unsanitized 3.4.12 build.
# Caller sets TOS_CODE (hex) in the environment and runs gdb -batch -x this
# file against lab/build/plain/ruby-3.4.12-plain/bin/ruby.
set pagination off
set confirm off
break regparse.c:4589 if *from > 0x100000
run lab/repro/ruby2shell-tos-steer.rb
printf "HIT code=%lu cc=%p bs=%p target=%p offset=%lu bit=%d\n", (unsigned long)*from, cc, cc->bs, (char *)cc->bs + ((int)(*from)/32)*4, ((char *)cc->bs + ((int)(*from)/32)*4) - (char *)cc->bs, (int)(*from)&31
set $target = (char *)cc->bs + ((int)(*from)/32)*4
x/1wx $target
x/4gx $target - 16
delete 1
watch -l *(unsigned int *)$target
continue
quit
