#!/bin/sh
# Provenance check for the W187 real-process Size-1 lane. Verifies pinned
# fixtures/logs and the observed fault differential. Does not launch a GUI;
# the replay recipe is in PROVENANCE-lowindex.md.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
PASS=0
FAIL=0

expect() {
    if grep -qF "$2" "$1"; then PASS=$((PASS+1));
    else FAIL=$((FAIL+1)); printf 'FAIL %s: missing %s\n' "$3" "$2"; fi
}
absent() {
    if grep -qF "$2" "$1"; then FAIL=$((FAIL+1)); printf 'FAIL %s: found %s\n' "$3" "$2";
    else PASS=$((PASS+1)); fi
}

sha256sum -c PINS-w187.sha256 >/dev/null
PASS=$((PASS+1))

# Byte-level provenance of the 13-byte same-length CFB stream patch at 0x2ae.
if dd if=fixtures/w187-size-1.SchLib bs=1 skip=686 count=13 2>/dev/null | grep -qF 'Size-1=9|||||'; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1)); printf 'FAIL hostile-fixture-patch\n'
fi
if dd if=fixtures/w187-safe-size1.SchLib bs=1 skip=686 count=13 2>/dev/null | grep -qF 'Size1=9|||||'; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1)); printf 'FAIL safe-fixture-patch\n'
fi

# Hostile run: SIGSEGV with frames in the real _eeschema.kiface.
expect evidence/w187-size-1-gdb.log \
    'Thread 1 "eeschema" received signal SIGSEGV, Segmentation fault.' 'hostile-sigsegv'
expect evidence/w187-size-1-gdb.log 'make_fcontext () from' 'hostile-kiface-frames'

# Matched safe control: process survived, no fault marker.
expect evidence/w187-safe-gdb.rc 'alive' 'safe-alive'
absent evidence/w187-safe-gdb.log 'received signal SIGSEGV' 'safe-no-sigsegv'
absent evidence/w187-safe-gdb.log 'double free or corruption' 'safe-no-abort'

# No rung-5 evidence is present in these logs.
absent evidence/w187-size-1-gdb.log 'marker' 'no-marker'

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
