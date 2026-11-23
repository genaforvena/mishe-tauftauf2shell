#!/bin/bash
# Real-object probe for CVE-2026-54789: verbatim pinned parser + real apr_pool_t,
# Apache request_rec, apr_table_t Cookie header, apr_pstrdup token, apr_strtok.
# NOT a full module, listener, socket or wire. No off-loopback probe.
# Every run re-extracts the slices from the byte-exact pinned blobs and checks
# src/SHA256SUMS. Results are layout-dependent under ASLR; the trace hash is
# descriptive, not a deterministic replay assertion.
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E" vuln fixed release
V=../src/state.c.4301b536
F=../src/state.c.8017478
R=../src/state.c.v2.4.19.4
{ echo '#line 105 "state.c.4301b536"'; sed -n '105,110p' "$V"; } > vuln/state_struct.inc
{ echo '#line 204 "state.c.4301b536"'; sed -n '204,223p' "$V"; } > vuln/parse_token.inc
{ echo '#line 105 "state.c.8017478"'; sed -n '105,110p' "$F"; } > fixed/state_struct.inc
{ echo '#line 204 "state.c.8017478"'; sed -n '204,226p' "$F"; } > fixed/parse_token.inc
{ echo '#line 105 "state.c.v2.4.19.4"'; sed -n '105,110p' "$R"; } > release/state_struct.inc
{ echo '#line 204 "state.c.v2.4.19.4"'; sed -n '204,226p' "$R"; } > release/parse_token.inc
(cd ../src && sha256sum -c SHA256SUMS) > "$E/pin-hashes.txt" 2>&1
PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
has() { if grep -qF "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi; }
count_eq() {
  n=$(printf '%s\n' "$1" | grep -cF "$2")
  if [ "$n" = "$3" ]; then ok "$4"; else no "$4"; fi
}
if grep -qF 'FAILED' "$E/pin-hashes.txt"; then no 'pinned-source-sha256'; else ok 'pinned-source-sha256'; fi
if sha256sum -c SHA256SUMS > "$E/realobj-hashes.txt" 2>&1; then ok 'realobj-sha256-manifest'; else no 'realobj-sha256-manifest'; fi

INC="-I/usr/include/apache2 $(pkg-config --cflags apr-1)"
LIB="$(pkg-config --libs apr-1 apr-util-1)"
gcc -O0 -g -std=gnu11 -fsanitize=address $INC -o a-vuln driver.c $LIB 2> "$E/build-vuln.log" && ok 'build-asan-vuln' || no 'build-asan-vuln'
gcc -O0 -g -std=gnu11 -fsanitize=address -DFIXED_VARIANT $INC -o a-fixed driver.c $LIB 2> "$E/build-fixed.log" && ok 'build-asan-fixed' || no 'build-asan-fixed'
gcc -O0 -g -std=gnu11 -fsanitize=address -DRELEASE_VARIANT $INC -o a-release driver.c $LIB 2> "$E/build-release.log" && ok 'build-asan-release' || no 'build-asan-release'
gcc -O0 -g -std=gnu11 $INC -o p-vuln driver.c $LIB 2> "$E/build-plain-vuln.log" && ok 'build-plain-vuln' || no 'build-plain-vuln'
gcc -O0 -g -std=gnu11 -DFIXED_VARIANT $INC -o p-fixed driver.c $LIB 2> "$E/build-plain-fixed.log" && ok 'build-plain-fixed' || no 'build-plain-fixed'
gcc -O0 -g -std=gnu11 -DRELEASE_VARIANT $INC -o p-release driver.c $LIB 2> "$E/build-plain-release.log" && ok 'build-plain-release' || no 'build-plain-release'

: > "$E/raw-trials.txt"
for f in 0 512 4000 8000; do
  for t in 1 2 3 4 5; do
    printf '\n=== VULN FILL=%s TRIAL=%s ===\n' "$f" "$t" >> "$E/raw-trials.txt"
    timeout 20 ./a-vuln read "$f" >> "$E/raw-trials.txt" 2>&1
  done
done
for b in a-fixed a-release; do
  for f in 0 512; do
    for t in 1 2 3 4 5; do
      printf '\n=== %s FILL=%s TRIAL=%s ===\n' "$b" "$f" "$t" >> "$E/raw-trials.txt"
      timeout 20 ./$b read "$f" >> "$E/raw-trials.txt" 2>&1
    done
  done
done
for gap in 1 17 33; do
  for b in p-vuln p-fixed p-release; do
    printf '\n=== %s WRITE GAP=%s ===\n' "$b" "$gap" >> "$E/raw-trials.txt"
    timeout 20 ./$b write 512 "$gap" >> "$E/raw-trials.txt" 2>&1
  done
done

RAW="$E/raw-trials.txt"
VULN=$(awk '/^=== VULN /{p=1} /^=== (a-|p-)/{p=0} p' "$RAW")
FIXED=$(awk '/^=== a-fixed /{p=1} /^=== (a-release|p-)/{p=0} p' "$RAW")
RELEASE=$(awk '/^=== a-release /{p=1} /^=== p-/{p=0} p' "$RAW")
READ_FAULTS=$(printf '%s\n' "$VULN" | grep -cF '4301b536:214 in oidc_state_cookies_parse_token')
WRITE_FAULTS=$(printf '%s\n' "$VULN" | grep -cF '4301b536:219 in oidc_state_cookies_parse_token')
DISPATCH=$(printf '%s\n' "$VULN" | grep -cF 'PROCESS_CALLS=1')
CTLF=$(printf '%s\n' "$FIXED" | grep -cF 'ERROR: AddressSanitizer')
CTLR=$(printf '%s\n' "$RELEASE" | grep -cF 'ERROR: AddressSanitizer')
printf 'VULN_TRIALS=20 READ_FAULTS=%s WRITE_FAULTS=%s DISPATCH=%s\n' "$READ_FAULTS" "$WRITE_FAULTS" "$DISPATCH" > "$E/summary.txt"
printf 'FIXED_ASAN_REPORTS=%s RELEASE_ASAN_REPORTS=%s\n' "$CTLF" "$CTLR" >> "$E/summary.txt"
printf 'PLAIN_VULN:\n' >> "$E/summary.txt"
sed -n '/=== p-vuln WRITE/,/===/p' "$RAW" | grep -E 'TOKEN_LEN|EQ_OFFSET|NUL_AT_OFFSET|BYTE_|VARIANT' >> "$E/summary.txt" || true
if [ $((READ_FAULTS + WRITE_FAULTS)) -gt 0 ]; then ok 'asan-fault-in-verbatim-parser'; else no 'asan-fault-in-verbatim-parser'; fi
printf 'INFO asan-write-faults=%s (layout-dependent; not asserted)\n' "$WRITE_FAULTS"
if [ "$DISPATCH" -gt 0 ]; then ok 'adjacent-equals-dispatched-in-real-pool'; else no 'adjacent-equals-dispatched-in-real-pool'; fi
if [ "$CTLF" = 0 ] && [ "$CTLR" = 0 ]; then ok 'fixed-and-release-asan-clean'; else no 'fixed-and-release-asan-clean'; fi
count_eq "$FIXED" 'VARIANT=fixed-8017478 RC=0 PROCESS_CALLS=0' 10 'fixed-rejects-all-10-trials'
count_eq "$RELEASE" 'VARIANT=release-v2.4.19.4 RC=0 PROCESS_CALLS=0' 10 'release-rejects-all-10-trials'
PV=$(grep -A4 -F '=== p-vuln WRITE GAP=1 ===' "$RAW")
if printf '%s\n' "$PV" | grep -qF 'RC=1 PROCESS_CALLS=1'; then ok 'plain-vuln-dispatched-at-gap-1'; else no 'plain-vuln-dispatched-at-gap-1'; fi
for off in 31 47 63; do
  has "$RAW" "NUL_AT_OFFSET=$off" "plain-nul-at-$off"
done

grep -E '^(VARIANT=|FIRST_MUTATION_OFFSET=|EQ_IN_POOL_OFFSET=|ERROR: AddressSanitizer|SUMMARY: AddressSanitizer)' "$RAW" \
  | sed -E 's#/[^ ]*/realobj/##g; s/==[0-9]+==/==PID==/g; s/0x[0-9a-f]+/0xADDR/g' > "$E/normalized.txt"
TRACE=$(sha256sum "$E/normalized.txt" | cut -d' ' -f1)
printf 'TRACE_SHA256=%s\n' "$TRACE" >> "$E/summary.txt"
cat "$E/summary.txt"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
