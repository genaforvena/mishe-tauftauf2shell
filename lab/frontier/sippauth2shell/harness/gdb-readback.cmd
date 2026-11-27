set pagination off
set confirm off
break auth.cpp:190
run 64
printf "HIT_LINE_190 pc=%p\n", $pc
info locals
x/12bx algo+32
x/2gx $rbp
x/2gx $rbp+8
bt 3
continue
