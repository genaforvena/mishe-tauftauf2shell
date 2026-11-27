# W367: observe the second fold's overflow write directly.
# Run from the repository root:
#   gdb -q -batch -x lab/repro/ruby2shell-twofold-watch.gdb \
#       lab/build/plain/ruby-3.4.12-plain/bin/ruby
# The watchpoint is armed on the second case_map call's to_end (the argument's
# fold); the trap must land in case_map at enc/iso_8859_1.c:293 with a 0x73 byte.
set pagination off
set confirm off
break string.c:7839
commands
silent
set $n = $n + 1
printf "CALL n=%d to=%p to_end=%p capa=%ld\n", $n, $rcx, $r8, $r8 - $rcx
if $n == 3
    set $addr = $r8
    watch *(unsigned char *) $addr
    printf "WATCH-SET addr=%p\n", $addr
end
continue
end
set $n = 0
run lab/repro/ruby2shell-twofold.rb 27 43
printf "STOP pc=%p addr=%p\n", $pc, $addr
bt 6
x/1bx $addr
continue
quit
