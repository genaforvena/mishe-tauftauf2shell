set pagination off
set confirm off
set breakpoint pending on
break ccx_gxf.c:1220
run
set $buf = (unsigned long)data->buffer
set $p = $buf + 2097264
set $gxf = (struct ccx_gxf *)demux->private_data
printf "W6LAYOUT AT_PARSE buf=0x%lx P=0x%lx top=0x%lx vid=0x%lx ad=0x%lx\n", $buf, $p, main_arena.top, (unsigned long)$gxf->vid_track, (unsigned long)$gxf->ad_track
printf "W6LAYOUT HDR prev=0x%lx size=0x%lx fd=0x%lx bk=0x%lx\n", *(unsigned long*)$p, *(unsigned long*)($p+8), *(unsigned long*)($p+16), *(unsigned long*)($p+24)
break free if $rdi == $buf
continue
printf "W6LAYOUT AT_FREE buf=0x%lx P=0x%lx top=0x%lx vid=0x%lx ad=0x%lx\n", $buf, $p, main_arena.top, (unsigned long)$gxf->vid_track, (unsigned long)$gxf->ad_track
printf "W6LAYOUT HDR_FREE prev=0x%lx size=0x%lx fd=0x%lx bk=0x%lx\n", *(unsigned long*)$p, *(unsigned long*)($p+8), *(unsigned long*)($p+16), *(unsigned long*)($p+24)
bt 3
quit
