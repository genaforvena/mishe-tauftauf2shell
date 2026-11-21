set pagination off
set confirm off
set args -b 127.0.0.1 -p 18098 -d /home/mesh-home/mishe-tauftauf2shell/lab/gpfdist2shell-live/out_gdblayout/data -l /home/mesh-home/mishe-tauftauf2shell/lab/gpfdist2shell-live/out_gdblayout/server.log
break gpfdist_v7.6.1.c:3677
commands
silent
printf "\n=== LAYOUT segid=%ld seq=%ld ===\n", r->segid, r->seq
printf "active_segids=%p seq_segs=%p\n", session->active_segids, session->seq_segs
printf "session=%p\n", session
printf "path=%p key=%p tid=%p fstream=%p requests=%p\n", session->path, session->key, session->tid, session->fstream, session->requests
printf "96 bytes from active_segids-16:\n"
x/96bx (char*)session->active_segids-16
printf "16 pointer-sized words from active_segids-16:\n"
x/16gx (char*)session->active_segids-16
continue
end
run
