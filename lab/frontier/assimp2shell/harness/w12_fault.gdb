# W12: capture the fault address and frame class of the real importer crash.
#   gdb -q -batch -x harness/w12_fault.gdb --args DRIVER CASE.gltf
set pagination off
set confirm off
run
printf "FAULT si_addr=%p\n", $_siginfo._sifields._sigfault.si_addr
bt 6
