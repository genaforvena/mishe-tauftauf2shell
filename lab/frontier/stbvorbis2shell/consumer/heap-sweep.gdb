# W207 grooming sweep: pass the input with -ex 'set args FILE'.
set pagination off
set confirm off
break stb_vorbis.h:4043
break stb_vorbis.h:4054
run
printf "W207_PRE mult=%p\n", c->multiplicands
x/20gx c->multiplicands-16
continue
printf "W207_POST mult=%p j=%d k=%d\n", c->multiplicands, j, k
x/20gx c->multiplicands-16
quit
