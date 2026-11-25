# W25: measure a 16-byte VEC4 index write against canary and saved-RIP slots.
# The first memcpy@plt with len=16 and a stack destination on this path is
# Accessor::Indexer::GetValue's copy into the 4-byte `value` local.
set pagination off
set confirm off
start
break memcpy@plt if ($rdx == 16 || $rdx == 64) && $rdi > 0x700000000000
continue
printf "W25_HIT dest=%p src=%p len=%lu\n", $rdi, $rsi, $rdx
python
import gdb
dest = int(gdb.parse_and_eval("$rdi"))
canary = int(gdb.parse_and_eval("*(unsigned long*)((char*)$fs_base + 0x28)"))
inf = gdb.selected_inferior()
data = bytes(inf.read_memory(dest - 256, 1024))
needle = canary.to_bytes(8, 'little')
slots = []
pos = 0
while True:
    idx = data.find(needle, pos)
    if idx < 0:
        break
    slots.append(idx - 256)
    pos = idx + 1
print("W25_CANARY %s" % ",".join(map(str, slots)))
f = gdb.newest_frame()
i = 0
while f and i < 5:
    gdb.execute("frame %d" % i, to_string=True)
    out = gdb.execute("info frame", to_string=True)
    for line in out.splitlines():
        if "rip at" in line:
            slot = int(line.split("rip at ")[1].split()[0], 16)
            val = int.from_bytes(bytes(inf.read_memory(slot, 8)), 'little')
            print("W25_RIP frame=%d delta=%d val=%#x" % (i, slot - dest, val))
    f = f.older()
    i += 1
end
quit
