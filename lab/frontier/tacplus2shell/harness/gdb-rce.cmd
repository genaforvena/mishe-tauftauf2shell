set pagination off
set confirm off
set print elements 0

break author.c:78 if i == 14
commands
 silent
 printf "RCE14 t=%p TARGET=%p i=%d\n", t, t, (int)i
 printf "RCE14 target_after:\n"
 x/36bx t
 continue
end

break mem_destroy
commands
 silent
 printf "RCE_DESTROY m=%p type=%u count=%u arr=%p\n", m, *(unsigned *)((char *)m + 8), *(unsigned *)((char *)m + 12), *(void **)((char *)m + 16)
 if *(unsigned *)((char *)m + 12) > 0
  printf "RCE_ENTRY f=%p p=%p\n", *(void **)(*(void **)((char *)m + 16)), *(void **)((char *)(*(void **)((char *)m + 16)) + 8)
 end
 continue
end

break system
commands
 silent
 printf "RCE_SYSTEM called arg=%p\n", $rdi
 x/s $rdi
 continue
end

run
printf "INFERIOR STOPPED\n"
bt 6
quit
