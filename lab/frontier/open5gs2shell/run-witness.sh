#!/usr/bin/env bash
# One-command replay of every open5gs2shell claim (CVE-2026-116543).
#
#   bash lab/frontier/open5gs2shell/run-witness.sh OUTDIR [PROV_SRC]
#
# Run it from a clean `git archive` of the committed tree. With no PROV_SRC it
# replays the five source suites (harness 21, realcaller 15, httpbody 8,
# wireloop 13, bytechoice 11 PASS) using only committed sources and the pinned
# parser. With PROV_SRC pointing at a lab tree that has the gitignored build/
# and local-prefix/ (four prebuilt open5gs-nrfd binaries plus the locally
# extracted dependency prefix), it also replays the live NRF: plain vulnerable,
# fixed, ASan vulnerable and ASan fixed, each over loopback-only h2c. The
# witness may substitute their own rebuilt binaries by pointing PROV_SRC at
# their own tree; the wrapper records the SHA-256 of every binary it uses.
# A clean-archive rebuild recipe for those binaries is in
# reports/frontier-open5gs2shell.md under "Clean-archive ASan receipt" and
# "Clean-archive receipt" (W5/W6).
#
# No external host is contacted: all listeners bind 127.0.0.1. All new logs go
# to OUTDIR; the suite evidence files inside the tree are rewritten by the
# unmodified suite runners. This wrapper makes no grade claim; it is offered
# so an independent role can produce a verdict on #4225/#4263/#4171.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 2
OUT="${1:-$HERE/witness-out-$$}"
mkdir -p "$OUT" || exit 2
PROV_SRC="${2:-}"
pass=0
fail=0

ck() {
    if [ "$1" -eq 0 ]; then
        echo "PASS $2"
        pass=$((pass + 1))
    else
        echo "FAIL $2"
        fail=$((fail + 1))
    fi
}
need() {
    local file="$1" pattern="$2" label="$3"
    grep -qF -- "$pattern" "$file"
    ck $? "$label"
}
suite() {
    local name="$1" expected="$2"
    shift 2
    "$@" >"$OUT/$name.log" 2>&1
    local rc=$?
    ck "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "$name rc=0"
    need "$OUT/$name.log" "RESULT $expected PASS / 0 FAIL" "$name $expected PASS / 0 FAIL"
}

echo "=== open5gs2shell witness replay $(date -u +%FT%TZ) ==="
echo "TREE $HERE"
git rev-parse HEAD 2>/dev/null || echo "TREE no git metadata (clean archive)"
sha256sum -c pins.sha256 >"$OUT/pins.log" 2>&1
ck $? "top-level pins.sha256 exact"

suite harness 21 sh harness/run.sh
suite realcaller 15 sh realcaller/run.sh
suite httpbody 8 sh httpbody/run.sh
suite wireloop 13 sh wireloop/run.sh
suite bytechoice 11 sh harness/bytechoice/run.sh

need harness/evidence/asan-vuln-attack.out 'WRITE of size 1' \
    'harness ASan WRITE of size 1'
need harness/evidence/asan-vuln-attack.out '0 bytes after 65-byte region' \
    'harness ASan zero bytes past the 65-byte parser allocation'
need harness/evidence/asan-vuln-attack.out 'multipart_parser-v2.8.0.c:260' \
    'harness fault at pinned sink :260'
need harness/evidence/plain-vuln-attack.out \
    'CANARY-AFTER=0a000d0a000d0a000d0a000d' 'harness periodic canary bytes'
need realcaller/evidence/asan-attack.out 'BOUNDARY_LEN=0 BOUNDARY=' \
    'real-caller extraction derives the empty boundary'
need realcaller/evidence/asan-fixed-attack.out 'ERROR=Empty multipart boundary' \
    'real-caller fixed guard rejects'
need wireloop/evidence/wire.out \
    'WIRE case=attack-asan proto=HTTP/2.0 len=396 head=0d0a0d0a613a0d0a0d0a' \
    'loopback h2 delivers the exact 396 attack bytes'
need wireloop/evidence/wire.out 'RESULT wire-failures=0' 'wire cases all pass'
need harness/bytechoice/evidence/bytechoice.txt 'CANARY_CHANGED=7' \
    'forced periodic bytes change the adjacent canary'
need harness/bytechoice/evidence/bytechoice.txt 'CASE=all-0x41' \
    'arbitrary-byte arm present'

if [ -n "$PROV_SRC" ]; then
    SRC="$(cd "$PROV_SRC" && pwd)"
    BINS="build/bld/src/nrf/open5gs-nrfd build/bld-fixed/src/nrf/open5gs-nrfd build/bld-asan/src/nrf/open5gs-nrfd build/bld-fixed-asan/src/nrf/open5gs-nrfd"
    ok=0
    for b in $BINS; do
        [ -x "$SRC/$b" ] || { echo "MISSING $SRC/$b"; ok=1; }
    done
    [ -d "$SRC/local-prefix/usr/lib/x86_64-linux-gnu" ] || {
        echo "MISSING $SRC/local-prefix"
        ok=1
    }
    ck "$ok" "PROV_SRC has four NRF binaries and the local dependency prefix"
    if [ "$ok" -eq 0 ]; then
        [ -e "$HERE/build" ] || ln -s "$SRC/build" "$HERE/build"
        [ -e "$HERE/local-prefix" ] || ln -s "$SRC/local-prefix" "$HERE/local-prefix"
        (cd "$PROV_SRC" && sha256sum $BINS) >"$OUT/nrf-binary-sha256.txt"
        echo "NRF binaries hashed into $OUT/nrf-binary-sha256.txt"

        TAG=witness-plain sh nfloop/run.sh >"$OUT/nrf-plain.log" 2>&1
        rc=$?
        ck "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "plain NRF replay rc=0"
        need "$OUT/nrf-plain.log" \
            'CASE=attack curl_rc=56 nrf_alive=NO nrf_rc=134' \
            'plain vulnerable NRF killed by the attack (SIGABRT 134)'
        need "$OUT/nrf-plain.log" 'CASE=staged curl_rc=0 nrf_alive=YES nrf_rc=0' \
            'plain staged-body control alive'
        need "$OUT/nrf-plain.log" 'CASE=safe curl_rc=0 nrf_alive=YES nrf_rc=0' \
            'plain safe control alive'
        need "$OUT/nrf-plain.log" 'CASE=abc curl_rc=0 nrf_alive=YES nrf_rc=0' \
            'plain ABC control alive'

        TAG=witness-fixed NRF_BIN="$HERE/build/bld-fixed/src/nrf/open5gs-nrfd" \
            sh nfloop/run.sh >"$OUT/nrf-fixed.log" 2>&1
        rc=$?
        ck "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "fixed NRF replay rc=0"
        need "$OUT/nrf-fixed.log" \
            'CASE=attack curl_rc=0 nrf_alive=YES nrf_rc=0' \
            'fixed NRF rejects the attack and stays alive'
        need nfloop/evidence/witness-fixed-attack.stdout \
            'Empty multipart boundary' 'fixed guard fires in the live NRF'

        TAG=witness-asan ASAN_OPTIONS=detect_leaks=0 \
            NRF_BIN="$HERE/build/bld-asan/src/nrf/open5gs-nrfd" \
            sh nfloop/run.sh >"$OUT/nrf-asan.log" 2>&1
        rc=$?
        ck "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "ASan NRF replay rc=0"
        need "$OUT/nrf-asan.log" \
            'CASE=attack curl_rc=56 nrf_alive=NO nrf_rc=1' \
            'ASan vulnerable NRF dies on the attack'
        need nfloop/evidence/witness-asan-attack.stdout \
            'heap-buffer-overflow' 'live NRF ASan report'
        need nfloop/evidence/witness-asan-attack.stdout \
            'WRITE of size 1' 'live NRF ASan WRITE of size 1'
        need nfloop/evidence/witness-asan-attack.stdout \
            'multipart_parser.c:260' 'live NRF fault at pinned sink :260'
        need "$OUT/nrf-asan.log" 'CASE=safe curl_rc=0 nrf_alive=YES nrf_rc=0' \
            'ASan safe control alive'

        TAG=witness-asanfixed ASAN_OPTIONS=detect_leaks=0 \
            NRF_BIN="$HERE/build/bld-fixed-asan/src/nrf/open5gs-nrfd" \
            sh nfloop/run.sh >"$OUT/nrf-asanfixed.log" 2>&1
        rc=$?
        ck "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "ASan fixed NRF replay rc=0"
        need "$OUT/nrf-asanfixed.log" \
            'CASE=attack curl_rc=0 nrf_alive=YES nrf_rc=0' \
            'ASan fixed NRF rejects the attack and stays alive'
        need nfloop/evidence/witness-asanfixed-attack.stdout \
            'Empty multipart boundary' 'ASan fixed guard fires in the live NRF'
    fi
else
    echo "SKIP live-NRF lane: no PROV_SRC; pass a tree with build/ and local-prefix/"
fi

echo "RESULT: PASS=$pass FAIL=$fail"
if [ "$fail" -eq 0 ]; then
    echo "WITNESS_REPLAY_PASS rc=0"
    exit 0
fi
echo "WITNESS_REPLAY_FAIL rc=1"
exit 1
