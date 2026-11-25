set pagination off
run -script import-value-atkceiling-save.ff
printf "pc=%p\n", $pc
p/x pt
p/x bfc->bitmap
bt 4
quit
