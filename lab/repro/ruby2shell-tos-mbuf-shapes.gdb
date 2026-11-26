# Observe regparse.c:4589 hits for one shape probe. Caller sets TOS_CODE and
# TOS_SHAPE in the environment and runs gdb -batch -x this file against the
# unsanitized 3.4.12 Ruby. Records cc->mbuf and the encoding at each hit.
set pagination off
set confirm off
break regparse.c:4589 if *from >= 0x100
run lab/repro/ruby2shell-tos-mbuf-shapes.rb
printf "HIT code=%lu cc=%p bs=%p mbuf=%p enc=%s flags=%u target=%p bit=%d\n", (unsigned long)*from, cc, cc->bs, cc->mbuf, env->enc->name, cc->flags, (char *)cc->bs + ((int)(*from)/32)*4, (int)(*from)&31
continue
printf "HIT2 code=%lu mbuf=%p enc=%s\n", (unsigned long)*from, cc->mbuf, env->enc->name
continue
printf "HIT3 code=%lu mbuf=%p enc=%s\n", (unsigned long)*from, cc->mbuf, env->enc->name
quit
