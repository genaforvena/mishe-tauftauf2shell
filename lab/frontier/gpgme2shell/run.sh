#!/bin/sh
# CVE-2026-129975 harness: hash-pinned vulnerable source + fix, ASan/plain
# vulnerable/fixed and attack/safe controls. No network access.
set -u
cd "$(dirname "$0")" || exit 2
mkdir -p evidence
pass=0; fail=0
check() { if [ "$1" = "$2" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $3 (got '$1', want '$2')"; fi; }
hash() { sha256sum "$1" | cut -d' ' -f1; }

check "$(hash pinned/engine-gpg.c)" c4ef11bda841fc6d07c83063c6968a6db50db3393af2d661054c59b979311d55 "engine-gpg.c pin"
check "$(hash pinned/fix.patch)" 2fde658ab8b32439c14f58c214f2463b4109aa68d9cbd26c432f17303049c500 "fix.patch pin"
check "$(grep -c 'gpg->status.bufsize = bufsize;' pinned/engine-gpg.c)" 1 "end-of-function status writeback"
check "$(grep -c '^+      gpg->colon.bufsize = bufsize;' pinned/fix.patch)" 1 "fix adds colon writeback"
check "$(grep -c 'if (gpg->status.buffer)' pinned/engine-gpg.c)" 1 "cleanup free"

cc -std=c99 -g -O0 -fsanitize=address -fno-omit-frame-pointer -o vuln-asan harness.c || exit 2
cc -std=c99 -g -O0 -fsanitize=address -fno-omit-frame-pointer -DFIXED -o fixed-asan harness.c || exit 2
cc -std=c99 -g -O0 -o vuln-plain harness.c || exit 2
cc -std=c99 -g -O0 -DFIXED -o fixed-plain harness.c || exit 2
check 0 $? "all four builds"

run() { name=$1; bin=$2; mode=$3; byte=$4; off=$5
  "$bin" "$mode" "$byte" "$off" >"evidence/$name.out" 2>&1
  echo $? >"evidence/$name.rc"
}
run asan-vuln-attack ./vuln-asan attack 0x48 1000
run asan-vuln-safe ./vuln-asan safe 0x48 1000
run asan-fixed-attack ./fixed-asan attack 0x48 1000
run asan-fixed-safe ./fixed-asan safe 0x48 1000
run plain-vuln-attack ./vuln-plain attack 0x5a 1000
run plain-fixed-attack ./fixed-plain attack 0x5a 1000

check "$(cat evidence/asan-vuln-attack.rc)" 1 "ASan vulnerable attack faults"
check "$(grep -c 'ERROR: AddressSanitizer: attempting double-free' evidence/asan-vuln-attack.out)" 1 "ASan names double free"
check "$(grep -c 'freed by thread' evidence/asan-vuln-attack.out)" 1 "first free recorded"
check "$(grep -c 'previously allocated by thread' evidence/asan-vuln-attack.out)" 1 "realloc allocation recorded"
check "$(grep -c 'byte\[1000\]=0x48' evidence/asan-vuln-attack.out)" 1 "chosen byte visible in old buffer"
check "$(grep -c 'published=old' evidence/asan-vuln-attack.out)" 1 "stale pointer in context"
check "$(cat evidence/asan-vuln-safe.rc)" 0 "safe path clean under ASan"
check "$(grep -c 'published=new' evidence/asan-vuln-safe.out)" 1 "safe path publishes new pointer"
check "$(cat evidence/asan-fixed-attack.rc)" 0 "upstream fix clean under ASan"
check "$(cat evidence/asan-fixed-safe.rc)" 0 "fixed safe clean under ASan"
check "$(grep -c 'published=old' evidence/plain-vuln-attack.out)" 1 "plain stale pointer in context"
check "$(grep -c 'byte\[1000\]=0x5a' evidence/plain-vuln-attack.out)" 1 "second chosen byte visible"
echo "plain rc=$(cat evidence/plain-vuln-attack.rc) recorded, not asserted (glibc behavior varies)"
check "$(cat evidence/plain-fixed-attack.rc)" 0 "plain fixed attack clean"

echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
