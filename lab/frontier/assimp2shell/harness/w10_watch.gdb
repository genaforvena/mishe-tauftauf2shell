# W10 supporting observation: let the instrumented 64-byte copy complete by
# setting __memcpy_chk's object-size argument to 64, then watch the caller's
# live vector slot. GDB changes instrumentation only: the copied bytes still
# come from the crafted glTF document. The driver needs the gitignored
# fortify plain build (`build-min-plain-g`, configured with
# `-DCMAKE_CXX_FLAGS='-O1 -g -fno-omit-frame-pointer'`); build it with
# `g++ -O1 -g -I pins/assimp-6.0.6/include -I build-min-plain-g/include
# harness/placement_driver.cpp -L build-min-plain-g/bin -lassimp -o
# harness/bin/w10_plain_g`, then from lab/frontier/assimp2shell run
# `gdb -q -batch -x harness/w10_watch.gdb harness/bin/w10_plain_g`.
set pagination off
set confirm off
start harness/cases/idxptr-zero.gltf
break __memcpy_chk if $rdx == 64 && $rcx == 4
continue
printf "AT-CHK dest=%p src=%p len=%lu objsz=%lu\n", $rdi, $rsi, $rdx, $rcx
set $rcx = 64
frame 4
printf "CALLER aim_slot=%p meshes_slot=%p\n", &aim, &meshes
p aim
p meshes.size()
watch -l *(unsigned long*)&aim
watch -l *(unsigned long*)&meshes
frame 0
continue
printf "AFTER-WRITE\n"
frame 4
p aim
p meshes.size()
bt 5
