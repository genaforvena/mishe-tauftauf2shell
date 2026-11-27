set pagination off
set confirm off
break src/be_strlib.c:543
run inputs/format-overflow.be
python
import gdb
frame = gdb.newest_frame().older()
rbp = int(frame.read_register("rbp"))
addr = rbp + 8
raw = bytes(gdb.selected_inferior().read_memory(addr, 8))
print("SAVED_RIP_ADDR=0x%x" % addr)
print("SAVED_RIP_BYTES=" + raw.hex())
print("SAVED_RIP_VALUE=0x" + raw[::-1].hex())
end
