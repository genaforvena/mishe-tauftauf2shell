#!/bin/sh
# One-command witness replay for stbvorbis2shell W208/W209 (chat #4511,
# #4539, #4578). Extracts the COMMITTED HEAD into a fresh directory,
# symlinks the SDL/SDL_mixer dependencies read-only from this checkout, then
# replays the core suites. Nothing in the live lab tree is written.
#
#   sh lab/frontier/stbvorbis2shell/run-witness.sh /tmp/stbvorbis-witness-out
#
# Needs gcc, gdb, cmake, python3. Expected totals: 9 + 17 + 14 PASS, 0 FAIL.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel) || exit 2
OUT=${1:-}
[ -n "$OUT" ] || { echo "usage: $0 OUTDIR (fresh, outside the repo)"; exit 2; }
case "$OUT" in
  "$REPO"/*|"$REPO") echo "refusing an output dir inside the repo"; exit 2 ;;
esac
[ ! -e "$OUT" ] || { echo "refusing existing $OUT; pass a fresh path"; exit 2; }

SHA=$(git -C "$REPO" rev-parse HEAD) || exit 2
mkdir -p "$OUT/replay" || exit 2
git -C "$REPO" archive "$SHA" lab/frontier/stbvorbis2shell | tar -x -C "$OUT" || exit 2
printf 'SHA=%s UTC=%s OUT=%s\n' "$SHA" "$(date -u +%FT%TZ)" "$OUT" | tee "$OUT/replay/provenance.txt"

DEPS="$REPO/lab/frontier/sdlmixer2shell/deps"
D="$OUT/lab/frontier/sdlmixer2shell/deps"
mkdir -p "$D" || exit 2
# SDL3 binaries are read-only here; the SDL_mixer SOURCE is copied, never
# symlinked. A concurrent wake patched the live "vuln" header in place with
# the W206 fixed guard on 2026-11-25 23:43Z, which made a clean rebuild
# reject the attack. A private copy freezes the audited source for this run.
for dep in SDL3-3.4.0-build SDL-release-3.2.4; do
    [ -d "$DEPS/$dep" ] || { echo "missing dependency $DEPS/$dep"; exit 2; }
    ln -s "$DEPS/$dep" "$D/$dep" || exit 2
done
[ -d "$DEPS/SDL_mixer-vuln-src" ] || exit 2
cp -a "$DEPS/SDL_mixer-vuln-src" "$D/SDL_mixer-vuln-src" || exit 2
HDR="$D/SDL_mixer-vuln-src/src/stb_vorbis/stb_vorbis.h"
[ -f "$HDR" ] || exit 2
if grep -q 'W206 fixed control' "$HDR"; then
    echo "REFUSING: vulnerable SDL_mixer source carries the fixed-control guard"; exit 2
fi
sha256sum "$HDR" | tee "$OUT/replay/vendored-header.sha256"

L="$OUT/lab/frontier/stbvorbis2shell"
TOTAL_PASS=0; TOTAL_FAIL=0; SUITE_FAIL=0
suite() {
    name=$1; want=$2; shift 2
    printf '\n=== %s ===\n' "$name"
    sh "$L/$name" > "$OUT/replay/$name.log" 2>&1
    rc=$?
    line=$(grep -E '^TOTAL PASS=[0-9]+ FAIL=[0-9]+' "$OUT/replay/$name.log" | tail -1)
    printf '%s rc=%s %s\n' "$name" "$rc" "$line"
    p=$(printf '%s\n' "$line" | sed -n 's/.*PASS=\([0-9][0-9]*\).*/\1/p')
    f=$(printf '%s\n' "$line" | sed -n 's/.*FAIL=\([0-9][0-9]*\).*/\1/p')
    [ -n "$p" ] && p=$((p+0)) || p=0
    [ -n "$f" ] && f=$((f+0)) || f=99
    TOTAL_PASS=$((TOTAL_PASS+p)); TOTAL_FAIL=$((TOTAL_FAIL+f))
    [ "$rc" -eq 0 ] && [ "$p" -eq "$want" ] && [ "$f" -eq 0 ] || SUITE_FAIL=$((SUITE_FAIL+1))
}

suite run-all.sh 9
suite run-consumer-preload.sh 17
suite run-canonical.sh 14

printf '\nGRAND PASS=%s FAIL=%s SUITES_FAILED=%s\n' "$TOTAL_PASS" "$TOTAL_FAIL" "$SUITE_FAIL"
printf '\n-- key observations --\n'
grep -h -E 'WRITE of size 4|fp=0x|TOTAL PASS|CANON_POST|CANON_OK' \
    "$OUT"/replay/*.log "$L"/consumer/evidence/*.out 2>/dev/null | tail -40
[ "$SUITE_FAIL" -eq 0 ] && [ "$TOTAL_FAIL" -eq 0 ]
