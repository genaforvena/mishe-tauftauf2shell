set pagination off
set confirm off
set breakpoint pending on
break regexec.c:2528
commands
  silent
  if reg->num_repeat > 32768
    printf "ONIG_STACK n=%ld num_repeat=%d base=%p s=%p end=%p subject_delta=%ld\n", n, reg->num_repeat, alloca_base, s, end, (long)(s - (char *)alloca_base)
  end
  continue
end
break regexec.c:3845
commands
  silent
  if mem < 0
    printf "ONIG_WRITE mem=%d target=%p value=%ld s=%p end=%p target_delta=%ld\n", mem, &repeat_stk[mem], (long)(stk - stk_base), s, end, (long)((char *)&repeat_stk[mem] - (char *)s)
    x/4gx (char *)&repeat_stk[mem] - 16
  end
  continue
end
run
