# Same calibrated target as gdb_pointer.gdb, port 18122.
set pagination off
set confirm off
set args -b 127.0.0.1 -p 18122 -d /home/mesh-home/mishe-tauftauf2shell/lab/gpfdist2shell-live/out_pointer_chosen_18122/data -l /home/mesh-home/mishe-tauftauf2shell/lab/gpfdist2shell-live/out_pointer_chosen_18122/server.log
break gpfdist_v7.6.1.c:3677
commands
silent
printf "\n=== BEFORE STORE segid=%ld seq=%ld ===\n", r->segid, r->seq
printf "seq_segs=%p requests=%p target=%p offset=%ld\n", session->seq_segs, session->requests, (char*)session->seq_segs + 8*r->segid, ((char*)session->requests - (char*)session->seq_segs)/8
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
