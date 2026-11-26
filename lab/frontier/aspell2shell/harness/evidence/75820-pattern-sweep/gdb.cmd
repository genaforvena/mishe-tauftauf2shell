set pagination off
set confirm off
set $n = 0
set $dest = 0
break *0x5555557d0fac
commands
silent
set $n = $n + 1
if $n == 1
  set $dest = $r14
  printf "BEFORE\n"
  x/40bx $dest
end
if $n <= 41
  printf "HIT %d dest=%p raw=%c norm=%d\n", $n, $r14, $rcx, $r12
end
if $n == 41
  printf "AFTER41\n"
  x/40bx $dest
end
continue
end
run --lang=en --dont-validate-words --dict-dir=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/aspell2shell/real-build/en-install/dict --data-dir=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/aspell2shell/real-build/en-install/data --personal=/tmp/aspell-pattern-evidence/personal-pattern -a < /tmp/aspell-pattern-evidence/query-pattern
quit
