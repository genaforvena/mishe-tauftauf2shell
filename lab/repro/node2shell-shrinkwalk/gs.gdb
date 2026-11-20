set pagination off
source /home/mesh-home/mishe-tauftauf2shell/lab/repro/node2shell-shrinkwalk/walk.py
set confirm off
break nghttp2_submit_altsvc
commands
silent
python walk_unsorted()
continue
end
run lab/repro/node2shell-rung1-server.js 31941
bt 12
quit
