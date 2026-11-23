set pagination off
set confirm off
directory /home/mesh-home/mishe-tauftauf2shell/lab/frontier/libfontenc2shell/build-vuln/src
set breakpoint pending on
break encparse.c:495 if index > 0xffff
run crafted /home/mesh-home/mishe-tauftauf2shell/lab/frontier/libfontenc2shell/realpath/tmp/fonts/dummy.pcf
set $base = (char *)*enc
printf "STOPPED index=%u row_size=%u to=%u encbase=%p encsize=%u\n", index, row_size, to, $base, *encsize
printf "glibc malloc_usable_size=%lu\n", malloc_usable_size($base)
printf "chunk header before user pointer:\n"
x/4gx $base-16
printf "128 bytes straddling nominal end (enc+131072):\n"
x/16gx $base+131072-64
printf "target bytes at chosen index (before store):\n"
x/4gx $base+65790*2-8
printf "process mappings:\n"
info proc mappings
next
printf "target bytes at chosen index (after store):\n"
x/4gx $base+65790*2-8
continue
