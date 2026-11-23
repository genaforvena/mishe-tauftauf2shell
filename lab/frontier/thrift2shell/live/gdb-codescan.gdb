# Look for executable pointers in the 1024-byte window starting at rBuf_ after
# untransform() and after the first processor->process() call. The frame is a
# normal KV-header frame: no pointer patch. ASLR is on; addresses are raw
# evidence and are not committed.
set pagination off
set confirm off
set print pretty off
set breakpoint pending on
set disable-randomization off
set $rb = 0
python
import gdb
import struct

def scan_window():
    rb = int(gdb.parse_and_eval("$rb"))
    if not rb:
        print("SCAN_NO_ANCHOR")
        return
    pid = gdb.selected_inferior().pid
    exec_ranges = []
    heap_ranges = []
    for line in open("/proc/%d/maps" % pid):
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        lo, hi = (int(x, 16) for x in parts[0].split("-"))
        perms = parts[1]
        name = parts[5].strip() if len(parts) == 6 else ""
        if "x" in perms:
            exec_ranges.append((lo, hi, name))
        if "[heap]" in name:
            heap_ranges.append((lo, hi, name))
    data = bytes(gdb.selected_inferior().read_memory(rb, 1024))
    code_hits = []
    heap_hits = []
    nonzero = 0
    for off in range(0, 1024, 8):
        value = struct.unpack_from("<Q", data, off)[0]
        if value:
            nonzero += 1
        for lo, hi, name in exec_ranges:
            if lo <= value < hi:
                code_hits.append((off, value, name))
                break
        for lo, hi, name in heap_ranges:
            if lo <= value < hi:
                heap_hits.append((off, value, name))
                break
    print("SCAN_RBUF=0x%x NONZERO_QWORDS=%d EXEC_QWORDS=%d HEAP_QWORDS=%d" %
          (rb, nonzero, len(code_hits), len(heap_hits)))
    for off, value, name in code_hits:
        print("SCAN_CODE off=+%d val=0x%x map=%s" % (off, value, name))
    for off, value, name in heap_hits[:16]:
        print("SCAN_HEAP off=+%d val=0x%x map=%s" % (off, value, name))
end
break THeaderTransport.cpp:301
commands 1
 silent
 set $rb = rBuf_.get()
 printf "SCAN_ANCHOR rbuf=%p sz=%u\n", $rb, sz
 continue
end
break TConnectedClient.cpp:64
commands 2
 silent
 python scan_window()
 printf "SCAN_DONE\n"
 continue
end
run
