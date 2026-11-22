#!/bin/bash
# CVE-2026-115863 / GHSA-725f-6r9j-c4hf — direct-call ASan + stack-canary harness.
# Every run re-extracts get_domains() from the two pinned source snapshots and
# asserts SHA-256 before compiling. No connman build, no DHCPv6, no network.
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E"
rm -f "$E"/*.log "$E"/*.out "$E"/normalized.txt get_domains_fn.inc \
      a-vuln-gcc a-vuln-clang a-fixed-gcc p-vuln
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

# --- pinned source + verbatim slice assertions -----------------------------
[ "$(srcsha ../src/client-2.0.c)" = \
  722cccc072d658f6c9fded507e1deab8cd8a8837479c9215c88a4834f81fcb0f ] \
  && ok "pin-2.0-source-sha256" || no "pin-2.0-source-sha256"
[ "$(srcsha ../src/client-2.0-fixed.c)" = \
  d252cf019c960a3a9a60501429155cead2876269c79ab1cca7443b787f3c5c0e ] \
  && ok "fixed-source-sha256" || no "fixed-source-sha256"
[ "$(srcsha ../src/fix-miu-20261023.patch)" = \
  a9715aa5c7e757baa0afa0041e29e988f2e0500788697a4ed89b7d5528c49aa2 ] \
  && ok "fix-patch-sha256" || no "fix-patch-sha256"
[ "$(srcsha driver.c)" = \
  3c24f1b659c610e8ba2231cb1f76bc564c2620252bf0bea57b2e142a5d59de4f ] \
  && ok "driver-sha256" || no "driver-sha256"

extract() { sed -n '/^static GList \*get_domains/,/^}/p' "$1"; }
extract ../src/client-2.0.c > /tmp/connman-vuln.inc
extract ../src/client-2.0-fixed.c > /tmp/connman-fixed.inc
[ "$(srcsha /tmp/connman-vuln.inc)" = \
  090d8ea201196ea32892c95aaeb38d5b2a99c9a8ef41c4d081782b8a6f60a5c2 ] \
  && ok "verbatim-vulnerable-slice-sha256" || no "verbatim-vulnerable-slice-sha256"
[ "$(srcsha /tmp/connman-fixed.inc)" = \
  466360babe68e0cdf7abfa8d5e20c5dd7ad7bea05631ecf0f39f8f531241b0d9 ] \
  && ok "verbatim-fixed-slice-sha256" || no "verbatim-fixed-slice-sha256"

CCAVAIL=0
command -v gcc >/dev/null 2>&1 && CCAVAIL=1
CLANGAVAIL=0
command -v clang >/dev/null 2>&1 && CLANGAVAIL=1
[ "$CCAVAIL" = 1 ] && ok "gcc-available" || no "gcc-available"
[ "$CLANGAVAIL" = 1 ] && ok "clang-available" || no "clang-available"

CFLAGS="-g -O0 -fno-omit-frame-pointer -fsanitize=address"
build() { # out, compiler, incfile, extra
	cp "$3" get_domains_fn.inc
	# shellcheck disable=SC2086
	$2 $CFLAGS ${4:-} -w driver.c -o "$1" 2>"$E/build-$1.log"
	return $?
}
build a-vuln-gcc gcc /tmp/connman-vuln.inc && ok "build-vuln-gcc-asan" || no "build-vuln-gcc-asan"
if [ "$CLANGAVAIL" = 1 ]; then
	build a-vuln-clang clang /tmp/connman-vuln.inc && ok "build-vuln-clang-asan" || no "build-vuln-clang-asan"
fi
build a-fixed-gcc gcc /tmp/connman-fixed.inc && ok "build-fixed-gcc-asan" || no "build-fixed-gcc-asan"
cp /tmp/connman-vuln.inc get_domains_fn.inc
gcc -g -O0 -fno-omit-frame-pointer -DPLAIN -w driver.c -o p-vuln 2>"$E/build-p-vuln.log" \
  && ok "build-vuln-plain" || no "build-vuln-plain"

# ASan reports the access at an absolute frame offset; the delta past the
# 1026-byte dns_name region is the attacker-chosen jump byte minus one.
oob_delta() {
	local off end
	off=$(grep -oE 'offset [0-9]+ in frame' "$1" | head -1 | grep -oE '[0-9]+')
	end=$(grep -oE "\[[0-9]+, [0-9]+\) 'dns_name'" "$1" | head -1 \
	      | grep -oE ', [0-9]+\)' | grep -oE '[0-9]+')
	[ -n "$off" ] && [ -n "$end" ] && echo $((off - end)) || echo UNKNOWN
}

# --- rung 3: ASan stack-buffer-overflow in the verbatim function -----------
for k in 10 20 40 80; do
	./a-vuln-gcc attack 0x$k >"$E/vuln-gcc-asan-$k.out" 2>&1; RC=$?
	f="$E/vuln-gcc-asan-$k.out"
	[ "$RC" -ne 0 ] && ok "vuln-gcc-0x$k-nonzero-exit" || no "vuln-gcc-0x$k-nonzero-exit"
	has "$f" "ERROR: AddressSanitizer: stack-buffer-overflow" "vuln-gcc-0x$k-asan-stack-overflow"
	has "$f" "READ of size 1" "vuln-gcc-0x$k-asan-read-1"
	has "$f" "get_domains" "vuln-gcc-0x$k-frame-get_domains"
	has "$f" "dns_name" "vuln-gcc-0x$k-dns-name-object"
	has "$f" "USEDLEN=2048 LASTJUMP=$k FIRST_OOB_OFFSET=$((0x$k - 1))" "vuln-gcc-0x$k-crafted-input"
	[ "$(oob_delta "$f")" = "$((0x$k - 1))" ] \
	  && ok "vuln-gcc-0x$k-oob-delta-matches-chosen-stride" \
	  || no "vuln-gcc-0x$k-oob-delta-matches-chosen-stride"
done

if [ "$CLANGAVAIL" = 1 ]; then
	./a-vuln-clang attack 0x80 >"$E/vuln-clang-asan.out" 2>&1; VCRC=$?
	f="$E/vuln-clang-asan.out"
	[ "$VCRC" -ne 0 ] && ok "vuln-clang-nonzero-exit" || no "vuln-clang-nonzero-exit"
	has "$f" "ERROR: AddressSanitizer: stack-buffer-overflow" "vuln-clang-asan-stack-overflow"
	has "$f" "READ of size 1" "vuln-clang-asan-read-1"
	has "$f" "get_domains" "vuln-clang-frame-get_domains"
	[ "$(oob_delta "$f")" = "127" ] \
	  && ok "vuln-clang-oob-delta-127" || no "vuln-clang-oob-delta-127"
fi

# --- controls: fixed pin clean; safe DOMAIN_LIST clean ---------------------
./a-fixed-gcc attack 0x80 >"$E/fixed-gcc-asan.out" 2>&1; FGRC=$?
has "$E/fixed-gcc-asan.out" "USEDLEN=2048 LASTJUMP=80" "fixed-sees-same-input"
has "$E/fixed-gcc-asan.out" "RC=0 LIST_LEN=256" "fixed-returns-clean-list"
hasnt "$E/fixed-gcc-asan.out" "AddressSanitizer" "fixed-no-asan-report"
[ "$FGRC" -eq 0 ] && ok "fixed-clean-exit" || no "fixed-clean-exit"

./a-vuln-gcc safe >"$E/vuln-gcc-safe.out" 2>&1; SGRC=$?
has "$E/vuln-gcc-safe.out" "RC=0 LIST_LEN=1" "vuln-safe-clean-list"
hasnt "$E/vuln-gcc-safe.out" "AddressSanitizer" "vuln-safe-no-asan"
[ "$SGRC" -eq 0 ] && ok "vuln-safe-clean-exit" || no "vuln-safe-clean-exit"

./a-fixed-gcc safe >"$E/fixed-gcc-safe.out" 2>&1; FSRC=$?
has "$E/fixed-gcc-safe.out" "RC=0 LIST_LEN=1" "fixed-safe-clean-list"
hasnt "$E/fixed-gcc-safe.out" "AddressSanitizer" "fixed-safe-no-asan"
[ "$FSRC" -eq 0 ] && ok "fixed-safe-clean-exit" || no "fixed-safe-clean-exit"

# --- rung 4 (scoped): chosen '.' writes observed in caller stack -----------
for n in 1 2; do
	./p-vuln 0x80 >"$E/plain-canary-$n.out" 2>&1; PGRC=$?
	f="$E/plain-canary-$n.out"
	has "$f" "PLAIN LASTJUMP=80" "plain-$n-crafted-input"
	has "$f" "CANARY DOTS=69 FIRST=49 LAST=16301" "plain-$n-69-chosen-dot-writes"
	[ "$PGRC" -eq 0 ] && ok "plain-$n-clean-exit" || no "plain-$n-clean-exit"
done

# --- path-independent normalized content hash -----------------------------
cat "$E"/*.out 2>/dev/null \
  | grep -E '^(USEDLEN=|PLAIN |CANARY |RC=|ERROR: AddressSanitizer:|READ of size|SUMMARY: AddressSanitizer:|    #[0-9]+ .* get_domains|    #[0-9]+ .* dns_name)' \
  | sed -E -e 's/0x[0-9a-f]{6,}/0xADDR/g' \
           -e 's#/[^ ]*(get_domains_fn\.inc|driver\.c)#PATH/\1#g' \
  > "$E/normalized.txt"
HASH=$(sha256sum "$E/normalized.txt" | cut -d' ' -f1)
printf 'NORMALIZED_HASH=%s\n' "$HASH"
printf 'SUMMARY=%d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
