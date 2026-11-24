# W186: watch the W184 COPY2 overwrite of the adjacent live malloc chunk
# header in UNMODIFIED exrcheck -c.  The run line is supplied by the caller:
#   gdb -q -batch -ex 'set pagination off' -ex 'set confirm off' \
#     -ex 'set disable-randomization on' \
#     -ex 'break sort2_4ByteChannels_tiled' -ex "run -c FILE" \
#     -x harness/chunk-header.cmd build-vuln-plain/bin/exrcheck
delete 1
set $base = (long)outPtr
set $srcbase = (long)inPtr
python
import gdb
inf = gdb.selected_inferior()
d = int(gdb.parse_and_eval("$base"))
def u64(a):
    return int.from_bytes(bytes(inf.read_memory(a, 8)), "little")
print("ENTRY own_size=0x%x next_prev=0x%x next_size=0x%x"
      % (u64(d - 8), u64(d + 256), u64(d + 264)))
end
watch *(unsigned long*)($base+264)
continue
printf "WATCH hit\n"
python
import gdb
inf = gdb.selected_inferior()
d = int(gdb.parse_and_eval("$base"))
s = int(gdb.parse_and_eval("$srcbase"))
def u64(a):
    return int.from_bytes(bytes(inf.read_memory(a, 8)), "little")
print("WATCH next_prev=0x%x next_size=0x%x src8=%s"
      % (u64(d + 256), u64(d + 264), bytes(inf.read_memory(s, 16)).hex()))
end
continue
printf "FINISHED\n"
quit
