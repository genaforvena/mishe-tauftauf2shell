# Calibrated from the 11:59:35Z run: seq_segs=0x...1a8, requests=0x...288,
# so requests[0] (the APR hash pool pointer) is at seq_segs + 8*28.
set pagination off
set confirm off
set args -b 127.0.0.1 -p 18121 -d /home/mesh-home/mishe-tauftauf2shell/lab/gpfdist2shell-live/out_pointer_18121/data -l /home/mesh-home/mishe-tauftauf2shell/lab/gpfdist2shell-live/out_pointer_18121/server.log
break gpfdist_v7.6.1.c:3677
commands
silent
printf "\n=== BEFORE STORE segid=%ld seq=%ld ===\n", r->segid, r->seq
printf "calibration: requests - seq_segs = %ld bytes = %ld indices\n", (char*)session->requests - (char*)session->seq_segs, ((char*)session->requests - (char*)session->seq_segs)/8
printf "seq_segs=%p active_segids=%p requests=%p target=%p\n", session->seq_segs, session->active_segids, session->requests, (char*)session->seq_segs + 8*r->segid
printf "requests[0] word before:\n"
x/gx session->requests
printf "8 bytes at target before:\n"
x/8bx (char*)session->seq_segs + 8*r->segid
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
