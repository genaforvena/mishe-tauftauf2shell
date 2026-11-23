set pagination off
set confirm off
set follow-fork-mode parent
set print elements 0
# cmd_qtdpsrc is inlined: +1988 is the call to hex2bin at source line 2547,
# +1998 is just after it, +2010 is the XNEW(source_string) result at 2550.
# $rsi at the call is the xmalloc(slen+1) buffer.
break *handle_tracepoint_general_set+1988
commands
 silent
 set $src = $rsi
 set $cnt = $rdx
 printf "\n=== BP_CALL src=%p count=%ld ===\n", $src, $cnt
 x/6gx $src-16
 x/12gx $src+24
 x/96bx $src
 continue
end
break *handle_tracepoint_general_set+1998
commands
 silent
 printf "\n=== BP_RET src=%p nbytes=%ld ===\n", $src, $rax
 x/6gx $src-16
 x/12gx $src+24
 x/96bx $src
 continue
end
break *handle_tracepoint_general_set+2010
commands
 silent
 printf "\n=== BP_NEWLAST newlast=%p chunkhdr: ===\n", $rax
 x/6gx $rax-16
 continue
end
run
printf "\n=== AFTER_RUN ===\n"
bt 12
info registers rip rdi rsi
x/16i $rip-24
p/x system
