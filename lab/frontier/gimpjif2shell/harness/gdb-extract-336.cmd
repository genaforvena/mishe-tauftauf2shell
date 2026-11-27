# W336: no-shim, no-patched-byte harness observation of the extraction loop.
# Positive control: an access watchpoint on indexes+260 must fire on the
# inflate WRITE. Then, at the pinned extraction store, arm read-only
# watchpoints on out-of-object words, run to the pinned function's last
# statement, and delete the watches before the driver's own canary readback.
set pagination off
set confirm off
break pins/jif-vulnerable.inc:106
run
set $w336idx = indexes
set $w336avail = zs.avail_out
printf "W336 IDX=%p DATA_SIZE=%u AVAIL=%u\n", $w336idx, data_size, $w336avail
awatch *(unsigned char *) ($w336idx + 260)
continue
printf "W336 WRITE WATCH FIRED (pre-inflate AVAIL=%u); resuming inflate\n", $w336avail
delete 2
break pins/jif-vulnerable.inc:125
continue
printf "W336 EXTRACTION STORE REACHED i=%d pos=%u total_out=%lu\n", i, pos, zs.total_out
break pins/jif-vulnerable.inc:136
rwatch *(unsigned char *) ($w336idx + 260)
rwatch *(unsigned char *) ($w336idx + 280)
rwatch *(unsigned char *) ($w336idx + 336)
disable 3
continue
printf "W336 PIN COMPLETE pos=%u total_out=%lu; read watches end here\n", pos, zs.total_out
delete 5
delete 6
delete 7
continue
printf "W336 READ PHASE DONE\n"
