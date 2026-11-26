#!/bin/sh
# W20: reproducible header-valid vs malformed-RR boundary check for the
# verbatim pinned display_ipopt(). Builds both objects from a clean copy of
# the tracked pinned source + fix patch; no tracked source is edited.
set -u
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
base=$(CDPATH= cd -- "$here/.." && pwd)
PINNED_SHA=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
CC=${CC:-gcc}
CFLAGS='-O0 -g -std=gnu99 -Wall -Wno-unused -Wno-unused-result'
ASAN='-fsanitize=address'
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/src"
n=0
fails=0
pass() { n=$((n + 1)); printf 'PASS %02d: %s\n' "$n" "$1"; }
fail() { n=$((n + 1)); fails=$((fails + 1)); printf 'FAIL %02d: %s\n' "$n" "$1"; }

sha=$(sha256sum "$base/pinned/display_ipopt.c" | cut -d' ' -f1)
[ "$sha" = "$PINNED_SHA" ] && pass "pinned display_ipopt.c sha256 $sha" ||
	fail "pinned sha256 $sha"

cp "$base/pinned/display_ipopt.c" "$tmp/src/display_ipopt.c" &&
	patch -s -o "$tmp/src/fixed_display_ipopt.c" \
		"$base/pinned/display_ipopt.c" < "$base/pinned/fix.patch" &&
	cp "$base/standin/hping2.h" "$base/standin/globals.h" "$tmp/src/" &&
	$CC $CFLAGS $ASAN -I "$tmp/src" -c "$tmp/src/display_ipopt.c" \
		-o "$tmp/vuln.o" &&
	$CC $CFLAGS $ASAN -I "$tmp/src" -c "$tmp/src/fixed_display_ipopt.c" \
		-o "$tmp/fixed.o" &&
	$CC $CFLAGS $ASAN -I "$tmp/src" -c "$here/caller.c" -o "$tmp/caller.o" &&
	$CC $ASAN -o "$tmp/vuln" "$tmp/vuln.o" "$tmp/caller.o" &&
	$CC $ASAN -o "$tmp/fixed" "$tmp/fixed.o" "$tmp/caller.o" &&
	pass "ASan vulnerable + fixed objects built from tracked pins" ||
	fail "ASan object build"

# label, binary, optlen, ptr, want-rc, required text, forbidden text
run_case() {
	label=$1; bin=$2; optlen=$3; ptr=$4; want=$5; need=$6; forbid=$7
	ASAN_OPTIONS=detect_leaks=0 "$bin" "$optlen" "$ptr" > "$tmp/out" 2>&1
	rc=$?
	if [ "$rc" -eq "$want" ] &&
		{ [ -z "$need" ] || grep -q "$need" "$tmp/out"; } &&
		{ [ -z "$forbid" ] || ! grep -q "$forbid" "$tmp/out"; }; then
		pass "$label: rc=$rc, $need"
	else
		fail "$label: rc=$rc (want $want), log: $(tr '\n' ' ' < "$tmp/out" | cut -c1-200)"
	fi
}

run_case 'header-valid optlen=40 ptr=40 (i=36)' "$tmp/vuln" 40 40 0 \
	'RETURNED_CLEAN' 'ERROR: AddressSanitizer'
run_case 'header-valid optlen=44 ptr=44 (i=40)' "$tmp/vuln" 44 44 0 \
	'RETURNED_CLEAN' 'ERROR: AddressSanitizer'
run_case 'malformed optlen=45 ptr=45 (i=41)' "$tmp/vuln" 45 45 1 \
	'global-buffer-overflow' ''
run_case 'malformed optlen=255 ptr=72 (i=68)' "$tmp/vuln" 255 72 1 \
	'WRITE of size 68' ''
run_case 'fixed source optlen=255 ptr=255' "$tmp/fixed" 255 255 0 \
	'RETURNED_CLEAN' 'ERROR: AddressSanitizer'

printf 'REPLAY_VALIDRR: %s checks, %s failures\n' "$n" "$fails"
[ "$fails" -eq 0 ] || exit 1
exit 0
