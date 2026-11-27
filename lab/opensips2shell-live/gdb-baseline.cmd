set pagination off
set confirm off
set follow-fork-mode child
set detach-on-fork on
set breakpoint pending on
shell (sleep 3; python3 /home/mesh-home/mishe-tauftauf2shell/lab/opensips2shell-live/send_early.py 299 260 AAAAAAAA > /home/mesh-home/mishe-tauftauf2shell/lab/opensips2shell-live/artifacts-early/wire-baseline.log 2>&1) &
break uri_xmpp2sip
run
printf "\n=== BASELINE AT uri_xmpp2sip ===\n"
bt 8
frame 1
info registers rip rbp
x/4gx $rbp
info proc mappings
printf "\n=== END BASELINE ===\n"
quit
