set pagination off
set confirm off
break heap-chain.c:164
run
printf "BREAK: A=%p B=%p C=%p ov=%p\n", a, b, c, ov
printf "C before: nCount=%#x arr0=%#x\n", c->nCount, c->arr[0]
watch -l *(unsigned char *)c
continue
printf "WATCH HIT: C->nCount byte0=%#x (store came through ov)\n", c->nCount
bt 6
printf "C after watch: nCount=%#x arr0=%#x\n", c->nCount, c->arr[0]
quit
