# Same calibrated target as gdb_pointer.gdb, port 18124 and a 17-char
# data-directory name so the allocation layout matches the pointer run.
set pagination off
set confirm off
set args -b 127.0.0.1 -p 18124 -d /home/mesh-home/mishe-tauftauf2shell/lab/gpfdist2shell-live/out_pointer_18124/data -l /home/mesh-home/mishe-tauftauf2shell/lab/gpfdist2shell-live/out_pointer_18124/server.log
break gpfdist_v7.6.1.c:3677
commands
silent
printf "\n=== BEFORE STORE segid=%ld seq=%ld ===\n", r->segid, r->seq
# layout_offset is the constant (requests - seq_segs)/8, not the write index.
printf "seq_segs=%p requests=%p target=%p layout_offset=%ld\n", session->seq_segs, session->requests, (char*)session->seq_segs + 8*r->segid, ((char*)session->requests - (char*)session->seq_segs)/8
printf "requests[0] word before:\n"
x/gx session->requests
continue
end
break gpfdist_v7.6.1.c:3680
commands
silent
printf "=== AFTER STORE segid=%ld seq=%ld ===\n", r->segid, r->seq
printf "requests[0] word after:\n"
x/gx session->requests
printf "8 bytes at target after:\n"
x/8bx (char*)session->seq_segs + 8*r->segid
continue
end
run
