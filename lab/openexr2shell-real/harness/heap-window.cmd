# W185: does the survivable 128-byte chosen-byte copy in UNMODIFIED
# exrcheck -c overwrite a live control-flow pointer? No: zero code/rodata
# pointers in [dst,dst+128). Run from lab/openexr2shell-real:
#   gdb -q -batch -x harness/heap-window.cmd build-vuln-plain/bin/exrcheck
# The `run -c FILE` line is supplied by the caller so this serves both files.
set pagination off
set confirm off
set print pretty off
set disable-randomization on
break sort2_4ByteChannels_tiled
run -c work-mixed/poc_mixed_full_3c.exr
set $base = (long)outPtr
delete 1
break memcpy if $rdx == 128
continue
set $d = (long)$rdi
set $n = (long)$rdx
printf "COPY2 dst_off=%ld n=%ld\n", $d-$base, $n
python
import gdb, re
inf = gdb.selected_inferior()
d = int(gdb.parse_and_eval("$d")); n = int(gdb.parse_and_eval("$n"))
def u64(a):
    return int.from_bytes(bytes(inf.read_memory(a, 8)), "little")
maps = gdb.execute("info proc mappings", to_string=True)
code, rodata = [], []
exe = gdb.execute("info files", to_string=True)
m = re.search(r"Entry point: 0x([0-9a-f]+)", exe)
entry = int(m.group(1), 16) if m else 0
for line in maps.splitlines():
    p = line.split()
    if len(p) < 5 or not p[0].startswith("0x"):
        continue
    try:
        lo, hi, perm = int(p[0], 16), int(p[1], 16), p[4]
    except ValueError:
        continue
    if "x" in perm:
        code.append((lo, hi))
    elif "r" in perm and lo <= entry < hi:
        rodata.append((lo, hi))
hits = 0
for off in range(0, n, 8):
    v = u64(d + off)
    if any(lo <= v < hi for lo, hi in code) or any(lo <= v < hi for lo, hi in rodata):
        hits += 1
print("PTR-HITS total=%d" % hits)
heapvals = sum(1 for off in range(0, n, 8)
               if 0x500000000000 <= u64(d + off) < 0x600000000000)
print("HEAP-VALUES total=%d" % heapvals)
end
quit
