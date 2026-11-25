set pagination off
set confirm off
break ccx_gxf.c:1220
run
python
import gdb
inf = gdb.selected_inferior()
buf = int(gdb.parse_and_eval('(unsigned long)data->buffer'))
usable = int(gdb.parse_and_eval('(unsigned long)malloc_usable_size(data->buffer)'))
base = buf + 2097272
mem = bytes(inf.read_memory(base, 65536))
print("HEAPSCAN buffer=%x usable=%d boundary=%x" % (buf, usable, base))
hits = []
for off in range(0, 65536 - 7, 8):
    v = int.from_bytes(mem[off:off+8], 'little')
    if 0x400000 < v < 0x800000000000:
        try:
            s = gdb.execute('info symbol 0x%x' % v, to_string=True).strip()
        except Exception:
            s = 'ERR'
        if s and not s.startswith('No symbol'):
            hits.append((off, v, s))
print("HEAPSCAN codeptr_hits=%d" % len(hits))
for off, v, s in hits[:20]:
    print("HEAPSCAN off=%d addr=0x%x sym=%s" % (off, v, s))
end
quit
