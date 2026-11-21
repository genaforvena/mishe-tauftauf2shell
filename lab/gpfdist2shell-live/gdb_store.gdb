set pagination off
set confirm off
set args -b 127.0.0.1 -p 18091 -d /home/mesh-home/mishe-tauftauf2shell/lab/gpfdist2shell-live/out_gdb/data -l /home/mesh-home/mishe-tauftauf2shell/lab/gpfdist2shell-live/out_gdb/server.log
break gpfdist_v7.6.1.c:3677
run
printf "\n=== BEFORE STORE :3677 ===\n"
print r->segid
print r->seq
print session->active_segids
print session->seq_segs
print session->path
x/48bx session->seq_segs-16
next
printf "\n=== AFTER STORE :3677 ===\n"
print session->seq_segs
x/48bx session->seq_segs-16
printf "\n=== DONE ===\n"
quit
