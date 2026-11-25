#!/bin/bash
# Wake-21 bounded check: is there a fixed-address code/string route for an
# ASLR-on dispatch target in the lab build? Read-only; no process is started.
# Invocation: sh harness/check_fixed_address_route.sh
set -eu
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell
KRESD="$BASE/build/knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd"

echo "== ELF type =="
readelf -h "$KRESD" | grep -E 'Type:|Entry point address:'
echo "== PIE flag =="
readelf -d "$KRESD" | grep -E 'FLAGS_1'
echo "== command-execution imports in kresd dynamic symbols =="
if readelf -Ws "$KRESD" | awk '$7 == "UND" && $8 != "" {print $8}' | sort -u \
    | grep -E '(^|@)(system|popen|execve|execl|execv|posix_spawn|dlopen|fork)(@|$)' ; then
    echo "FOUND command import"
else
    echo "NONE: no system/popen/exec*/posix_spawn/dlopen/fork import"
fi
echo "== named command PLT entries =="
if objdump -d -j .plt "$KRESD" \
    | grep -E '<(system|popen|execve|execl|execv|posix_spawn|dlopen)@plt>' ; then
    echo "FOUND command PLT entry"
else
    echo "NONE: no command-execution PLT entry"
fi
