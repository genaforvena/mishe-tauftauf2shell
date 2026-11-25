set pagination off
set confirm off
break /home/mesh-home/mishe-tauftauf2shell/.mishe-tauftauf/tmp/aspell-75820-recover/replay-work/src-vuln/modules/speller/default/suggest.cpp:1484 if j == 64
set env ASAN_OPTIONS detect_leaks=0:halt_on_error=0:abort_on_error=0
run --lang=en --dont-validate-words --dict-dir=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/aspell2shell/real-build/en-install/dict --data-dir=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/aspell2shell/real-build/en-install/data --personal=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/aspell2shell/harness/evidence/75820-write/personal-vuln-a -a < /home/mesh-home/mishe-tauftauf2shell/lab/frontier/aspell2shell/harness/evidence/75820-write/query-a
x/8bx 0x50600000e880
next
x/8bx 0x50600000e880
quit
