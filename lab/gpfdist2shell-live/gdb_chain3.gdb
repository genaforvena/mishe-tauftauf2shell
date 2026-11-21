set pagination off
set confirm off
set args -b 127.0.0.1 -p 18097 -d /home/mesh-home/mishe-tauftauf2shell/lab/gpfdist2shell-live/out_gdbchain3/data -l /home/mesh-home/mishe-tauftauf2shell/lab/gpfdist2shell-live/out_gdbchain3/server.log
break gpfdist_v7.6.1.c:3677
commands
silent
printf "\n=== STORE HIT segid=%ld seq=%ld ===\n", r->segid, r->seq
printf "seq_segs=%p active_segids=%p path=%p\n", session->seq_segs, session->active_segids, session->path
printf "bytes at seq_segs+24 (== path[0..7]):\n"
x/8bx (char*)session->seq_segs+24
printf "path string:\n"
x/s session->path
continue
end
run
