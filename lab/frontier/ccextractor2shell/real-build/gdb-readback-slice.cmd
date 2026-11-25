set pagination off
set print pretty on
set confirm off
break ccx_gxf.c:1220
break lib_ccxr/src/common/bitstream.rs:396
run lab/frontier/ccextractor2shell/real-build/inputs/readback.gxf -o /tmp/ccx2shell-readback-slice.scc
printf "SLICE_1 data_len=%lu buffer=%p\n", data->len, data->buffer
continue
printf "SLICE_2 pos=%ld bits_left=%ld\n", self.pos, self.bits_left
print self.data
print self
bt 6
quit
