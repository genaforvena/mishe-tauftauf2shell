# Measure the realized first OOB store value at the 154th sink hit.
# gdb observes only; it never writes memory.
set pagination off
set breakpoint pending on
break j2k.c:5085
run
set $hit = 0
while $hit < 154
  continue
  set $hit = $hit + 1
end
printf "MEASURED_W1=%016lx\n", (unsigned long)l_current_pos
quit
