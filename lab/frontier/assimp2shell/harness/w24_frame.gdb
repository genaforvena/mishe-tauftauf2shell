# W24: measure the 64-byte MAT4 Indexer write against saved RIP slots.
# The first memcpy@plt call with len=64 and a stack destination on this path
# is Accessor::Indexer::GetValue's copy into the 4-byte `value` local.
set pagination off
set confirm off
start
break memcpy@plt if $rdx == 64 && $rdi > 0x700000000000
continue
printf "W24_HIT dest=%p src=%p len=%lu\n", $rdi, $rsi, $rdx
python
import gdb
dest = int(gdb.parse_and_eval("$rdi"))
print("W24_DEST %#x" % dest)
f = gdb.newest_frame()
i = 0
while f and i < 12:
    gdb.execute("frame %d" % i, to_string=True)
    out = gdb.execute("info frame", to_string=True)
    for line in out.splitlines():
        if "rip at" in line:
            slot = int(line.split("rip at ")[1].split()[0], 16)
            delta = slot - dest
            print("W24_RIP frame=%d delta=%d inwindow=%d" %
                  (i, delta, 1 if 0 <= delta < 64 else 0))
    f = f.older()
    i += 1
end
bt 5
quit
