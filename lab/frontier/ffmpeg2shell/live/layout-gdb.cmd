set pagination off
set confirm off
handle SIGPIPE nostop noprint pass
run -hide_banner -loglevel verbose -f data -i async:rist://@:5004 -show_packets
printf "FAULT pc=%p\n", $pc
p/x $_siginfo._sifields._sigfault.si_addr
info registers rip rdi rsi rdx rax rcx r8 r11
x/8i $pc-8
bt 8
frame 2
p *f
p/x f->buffer
p/x f->nb_elems
p/x f->offset_r
p/x f->offset_w
frame 4
p/x ring->fifo
quit
