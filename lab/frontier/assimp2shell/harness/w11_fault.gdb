# W11: record the clang-build fault site and the corrupted caller locals.
#   gdb -q -batch -x harness/w11_fault.gdb --args DRIVER CASE.gltf
set pagination off
set confirm off
run
printf "FAULT si_addr=%p rsi=%p rdi=%p\n", $_siginfo._sifields._sigfault.si_addr, $rsi, $rdi
frame 3
printf "FRAME3 count=%u stride=%p data=%p faces=%p\n", count, data.stride, data.data, faces
bt 6
