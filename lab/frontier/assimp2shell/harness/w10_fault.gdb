# W10: capture the SIGSEGV address from the real importer's corrupted
# std::vector<std::unique_ptr<aiMesh>> dereference. Used as:
#   gdb -q -batch -x harness/w10_fault.gdb --args DRIVER CASE.gltf
set pagination off
set confirm off
run
printf "FAULT si_addr=%p\n", $_siginfo._sifields._sigfault.si_addr
bt 6
