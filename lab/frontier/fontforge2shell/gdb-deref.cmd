set pagination off
run -script import-value-atk50-save.ff
printf "pc=%p\n", $pc
p/x pt
p/x bfc->bitmap
bt 8
quit
