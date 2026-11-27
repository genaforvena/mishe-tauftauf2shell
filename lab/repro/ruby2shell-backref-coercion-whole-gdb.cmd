# W333 read-only inspection of the whole-receiver equal-length shrink.
# Captures the rb_str_update_1 arguments at entry, then dumps the receiver
# object after the memmove at string.c:5778. No debugger writes.
set pagination off
set confirm off
set breakpoint pending on
p &((struct RString *)0)->as.embed.ary
break rb_str_update_1 if $rdx == 296 && $r9 == 296
commands
 silent
 set $w333obj = $rdi
 printf "W333ENTRY obj=%p beg=%ld len=%ld vlen=%ld\n", $w333obj, $rsi, $rdx, $r9
 continue
end
break string.c:5780
run
printf "W333HIT obj=%p\n", $w333obj
x/40bx $w333obj+24
x/8bx $w333obj+320
continue
quit
