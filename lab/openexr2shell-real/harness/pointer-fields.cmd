# W185: are W171's "live pointers inside the destination range" pointer
# FIELDS that the W184 overwrite can steer? No: the exr_decode_pipeline_t is
# stack-resident in the flat harness, so the heap range holds pointer VALUES
# only. Run from lab/openexr2shell-real:
#   gdb -q -batch -x harness/pointer-fields.cmd bin-vuln-plain/flat_harness
set pagination off
set confirm off
set print pretty off
set disable-randomization on
break sort2_4ByteChannels_tiled
run work-mixed/poc_mixed_full_3c.exr
set $base = (long)outPtr
delete 1
break memcpy if $rdx == 128
continue
printf "COPY2 dst_off=%ld n=%ld\n", (long)$rdi-$base, (long)$rdx
python
import gdb
base = int(gdb.parse_and_eval("$base"))
f = gdb.newest_frame()
while f is not None and (f.name() or "") != "main":
    f = f.older()
v = f.read_var("decode")
for name in ("scratch_buffer_1", "scratch_buffer_2"):
    p = v[name]
    a = int(p.address)
    print("FIELD %s stack=%d in_copy_window=%d" %
          (name, 1 if a > 0x700000000000 else 0,
           1 if base <= a < base + 128 else 0))
    gdb.execute("set $fld_%s = %d" % (name.split("_")[-1], a))
    gdb.execute("set $val_%s = %d" % (name.split("_")[-1], int(p)))
end
finish
python
import gdb
for suffix in ("1", "2"):
    a = int(gdb.parse_and_eval("$fld_" + suffix))
    before = int(gdb.parse_and_eval("$val_" + suffix))
    after = int.from_bytes(bytes(gdb.selected_inferior().read_memory(a, 8)), "little")
    print("AFTER scratch_buffer_%s unchanged=%d" % (suffix, 1 if before == after else 0))
end
quit
