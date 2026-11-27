set pagination off
set confirm off
set follow-fork-mode child
set detach-on-fork on
set breakpoint pending on
handle SIGSEGV stop print
shell (sleep 3; python3 /home/mesh-home/mishe-tauftauf2shell/lab/opensips2shell-live/send_early.py 885 260 A > /home/mesh-home/mishe-tauftauf2shell/lab/opensips2shell-live/artifacts-early/wire-onebyte.log 2>&1) &
break uri_xmpp2sip
run
printf "\n=== AT uri_xmpp2sip ===\n"
tbreak *xmpp_send_sip_msg+631
continue
printf "\n=== AT RET ===\n"
info registers rip rsp rbp
x/4gx $rsp
x/4gx $rsp+8
x/i $rip
si
printf "\n=== AFTER RET ===\n"
info registers rip rsp rbp
x/i $rip
bt 4
printf "\n=== END ONEBYTE ===\n"
quit
