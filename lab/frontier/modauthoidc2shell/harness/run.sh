#!/bin/bash
# CVE-2026-54789 / GHSA-vgr5-qcpp-x2pr — mod_auth_openidc state-cookie scan.
# Every run re-extracts the two verbatim slices (record struct and
# oidc_state_cookies_parse_token) from the byte-exact pinned parent, fix commit
# and released tag, checks the two SHA-256 manifests, builds plain and ASan variants,
# and drives rungs 1-4. No daemon, no listener, no network, no off-loopback.
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E" vuln fixed release
rm -f "$E"/*.out "$E"/*.log "$E"/normalized.txt \
      vuln/*.inc fixed/*.inc release/*.inc \
      p-vuln p-fixed p-release a-vuln-gcc a-vuln-clang a-fixed-gcc a-release-gcc
PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() {
    if grep -qF "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi
}
hasnt() {
    if grep -qF "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi
}
count() {
    if [ "$(grep -cF "$2" "$1" 2>/dev/null)" = "$3" ]; then ok "$4"; else no "$4"; fi
}

# --- verbatim slices: re-extracted from pinned bytes on every run -----------
V=../src/state.c.4301b536
F=../src/state.c.8017478
R=../src/state.c.v2.4.19.4
{ echo '#line 105 "state.c.4301b536"'; sed -n '105,110p' "$V"; } > vuln/state_struct.inc
{ echo '#line 204 "state.c.4301b536"'; sed -n '204,223p' "$V"; } > vuln/parse_token.inc
{ echo '#line 105 "state.c.8017478"'; sed -n '105,110p' "$F"; } > fixed/state_struct.inc
{ echo '#line 204 "state.c.8017478"'; sed -n '204,226p' "$F"; } > fixed/parse_token.inc
{ echo '#line 105 "state.c.v2.4.19.4"'; sed -n '105,110p' "$R"; } > release/state_struct.inc
{ echo '#line 204 "state.c.v2.4.19.4"'; sed -n '204,226p' "$R"; } > release/parse_token.inc
(cd ../src && sha256sum -c SHA256SUMS) > "$E/hashcheck.out" 2>&1 \
  && ok "sha256-manifest" || no "sha256-manifest"
count "$E/hashcheck.out" ': OK' 4 'all-4-pinned-files-match'
sha256sum -c SHA256SUMS > "$E/hashcheck-harness.out" 2>&1 \
  && ok "harness-sha256-manifest" || no "harness-sha256-manifest"
count "$E/hashcheck-harness.out" ': OK' 12 'all-12-harness-and-pin-files-match'
count ../src/fix-8017478.patch 'while (cookie != NULL && *cookie != OIDC_CHAR_EQUAL)' 1 'patch-removes-dead-null-test'
count ../src/fix-8017478.patch 'while ((*cookie != '\''\0'\'') && (*cookie != OIDC_CHAR_EQUAL))' 1 'patch-adds-nul-bound-literal-check'
count vuln/parse_token.inc 'while (cookie != NULL && *cookie != OIDC_CHAR_EQUAL)' 1 'vuln-scan-unbounded'
count fixed/parse_token.inc 'while ((*cookie != '\''\0'\'') && (*cookie != OIDC_CHAR_EQUAL))' 1 'fixed-scan-nul-bounded'
count release/parse_token.inc 'while ((*cookie != '\''\0'\'') && (*cookie != OIDC_CHAR_EQUAL))' 1 'release-scan-nul-bounded'
count vuln/parse_token.inc 'while ((*cookie != '\''\0'\'') && (*cookie != OIDC_CHAR_EQUAL))' 0 'vuln-has-no-nul-bound'

# --- build ------------------------------------------------------------------
cc -O0 -g -std=gnu11 -o p-vuln driver.c 2> "$E/build-p-vuln.log" \
  && ok "build-plain-vuln" || no "build-plain-vuln"
cc -O0 -g -std=gnu11 -DFIXED_VARIANT -o p-fixed driver.c 2> "$E/build-p-fixed.log" \
  && ok "build-plain-fixed" || no "build-plain-fixed"
cc -O0 -g -std=gnu11 -DRELEASE_VARIANT -o p-release driver.c 2> "$E/build-p-release.log" \
  && ok "build-plain-release" || no "build-plain-release"
cc -O0 -g -std=gnu11 -fsanitize=address -o a-vuln-gcc driver.c \
  2> "$E/build-a-vuln-gcc.log" && ok "build-asan-gcc-vuln" || no "build-asan-gcc-vuln"
if command -v clang >/dev/null 2>&1; then
  clang -O0 -g -std=gnu11 -fsanitize=address -o a-vuln-clang driver.c \
    2> "$E/build-a-vuln-clang.log" && ok "build-asan-clang-vuln" || no "build-asan-clang-vuln"
else
  no "build-asan-clang-vuln"
fi
cc -O0 -g -std=gnu11 -DFIXED_VARIANT -fsanitize=address -o a-fixed-gcc driver.c \
  2> "$E/build-a-fixed-gcc.log" && ok "build-asan-gcc-fixed" || no "build-asan-gcc-fixed"
cc -O0 -g -std=gnu11 -DRELEASE_VARIANT -fsanitize=address -o a-release-gcc driver.c \
  2> "$E/build-a-release-gcc.log" && ok "build-asan-gcc-release" || no "build-asan-gcc-release"

# --- rung 1: advisory arithmetic, no vulnerable function call ---------------
./p-vuln arith > "$E/arith-vuln.out" 2>&1
has "$E/arith-vuln.out" 'PREFIX=mod_auth_openidc_state_' 'r1-attacker-supplied-prefix'
has "$E/arith-vuln.out" 'TOKEN_HAS_EQUAL=0' 'r1-valueless-token'
has "$E/arith-vuln.out" 'SCAN_EXIT_CONDITION=EQUAL_ONLY' 'r1-dead-null-test'
has "$E/arith-vuln.out" 'NUL_INDEX=30' 'r1-token-boundary'
has "$E/arith-vuln.out" 'BOUNDED_BY_NUL=0' 'r1-scan-unbounded'
has "$E/arith-vuln.out" 'EXPECTED_NUL_OFFSET=47' 'r1-predicted-write-offset'

# --- rungs 2+4: one NUL write at a chosen offset past the logical token ----
./p-vuln eqscan 17 > "$E/plain-eqscan-17.out" 2>&1
has "$E/plain-eqscan-17.out" 'RC=1' 'r2-state-cookie-dispatched'
has "$E/plain-eqscan-17.out" 'PROCESS_CALLS=1' 'r2-process-one-called'
has "$E/plain-eqscan-17.out" 'EQ_OFFSET=47 BYTE_AT_EQ_OFFSET=00' 'r2-nul-overwrote-equals'
has "$E/plain-eqscan-17.out" 'NUL_AT_OFFSET=47' 'r4-write-at-chosen-offset-47'
has "$E/plain-eqscan-17.out" 'CANARY=5a' 'r4-single-byte-write-only'
./p-vuln eqscan 1 > "$E/plain-eqscan-1.out" 2>&1
has "$E/plain-eqscan-1.out" 'NUL_AT_OFFSET=31' 'r4-write-at-chosen-offset-31'
./p-vuln eqscan 33 > "$E/plain-eqscan-33.out" 2>&1
has "$E/plain-eqscan-33.out" 'NUL_AT_OFFSET=63' 'r4-write-at-chosen-offset-63'

# --- rung 3: ASan READ one byte past the exact-size heap token -------------
./a-vuln-gcc asan-read > "$E/vuln-gcc-asan.out" 2>&1
has "$E/vuln-gcc-asan.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-gcc-asan-overflow'
has "$E/vuln-gcc-asan.out" 'READ of size 1' 'r3-gcc-asan-read1'
has "$E/vuln-gcc-asan.out" '31-byte region' 'r3-gcc-asan-at-token-end'
has "$E/vuln-gcc-asan.out" 'in oidc_state_cookies_parse_token' 'r3-gcc-asan-in-parse-token'
has "$E/vuln-gcc-asan.out" 'state.c.4301b536:214' 'r3-gcc-asan-at-pinned-line'
if [ -x a-vuln-clang ]; then
  ./a-vuln-clang asan-read > "$E/vuln-clang-asan.out" 2>&1
  has "$E/vuln-clang-asan.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-clang-asan-overflow'
  has "$E/vuln-clang-asan.out" 'READ of size 1' 'r3-clang-asan-read1'
  has "$E/vuln-clang-asan.out" '31-byte region' 'r3-clang-asan-at-token-end'
  has "$E/vuln-clang-asan.out" 'in oidc_state_cookies_parse_token' 'r3-clang-asan-in-parse-token'
fi

# --- fixed-commit and released-tag controls: reject before the write -------
./p-fixed eqscan 17 > "$E/fixed-eqscan.out" 2>&1
has "$E/fixed-eqscan.out" 'RC=0' 'fixed-rejects-valueless-token'
has "$E/fixed-eqscan.out" 'NUL_AT_OFFSET=0' 'fixed-no-out-of-bounds-write'
has "$E/fixed-eqscan.out" 'BYTE_AT_EQ_OFFSET=3d' 'fixed-equals-byte-intact'
has "$E/fixed-eqscan.out" 'PROCESS_CALLS=0' 'fixed-no-dispatch'
./a-fixed-gcc asan-read > "$E/fixed-gcc-asan.out" 2>&1
hasnt "$E/fixed-gcc-asan.out" 'ERROR: AddressSanitizer' 'fixed-asan-clean'
has "$E/fixed-gcc-asan.out" 'RC=0' 'fixed-asan-rejects'
./p-release eqscan 17 > "$E/release-eqscan.out" 2>&1
has "$E/release-eqscan.out" 'RC=0' 'release-rejects-valueless-token'
./a-release-gcc asan-read > "$E/release-gcc-asan.out" 2>&1
hasnt "$E/release-gcc-asan.out" 'ERROR: AddressSanitizer' 'release-asan-clean'

# --- safe control: a well-formed token stays in bounds in every variant ----
for B in p-vuln p-fixed p-release a-vuln-gcc a-fixed-gcc a-release-gcc; do
  ./"$B" safe > "$E/safe-${B}.out" 2>&1
  has "$E/safe-${B}.out" 'PROCESS_CALLS=1' "safe-${B}-dispatches"
  hasnt "$E/safe-${B}.out" 'ERROR: AddressSanitizer' "safe-${B}-asan-clean"
done

# --- deterministic normalized trace: no PID, address, path or build id ------
{
  cat "$E/arith-vuln.out" "$E/plain-eqscan-17.out" "$E/plain-eqscan-1.out" \
      "$E/plain-eqscan-33.out" "$E/fixed-eqscan.out" "$E/release-eqscan.out" \
      "$E/safe-p-vuln.out" "$E/safe-p-fixed.out" "$E/safe-p-release.out"
  cat "$E/vuln-gcc-asan.out" "$E/vuln-clang-asan.out" "$E/fixed-gcc-asan.out" \
      "$E/release-gcc-asan.out" "$E/safe-a-vuln-gcc.out" 2>/dev/null
} | sed -E 's#/[^ ]*modauthoidc2shell/harness/#HARNESS/#g; s#/[^ ]*/harness/#HARNESS/#g; s/BuildId: [0-9a-f]+/BuildId: BUILDID/g; s/0x[0-9a-f]+/0xADDR/g; s/#[0-9]+ /#FRAME /g; s/==[0-9]+==/==PID==/g' > "$E/normalized.txt"
TRACE=$(sha256sum "$E/normalized.txt" | cut -d' ' -f1)
printf 'TRACE_SHA256=%s\n' "$TRACE"

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
