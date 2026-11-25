#!/usr/bin/env bash
# W18 source-bound check: is the no-size TERM getter and the adjacent-field
# layout present in the SHIPPED 3.21e release, not only in the pinned dev
# parent 42f586d7?
# Provisioning only: fetches four raw files from the GitHub mirror at the
# exact commit the mirror's sbbs321e tag names. No runtime is started here.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "$HERE/.." && pwd)"
EVID="$HERE/evidence"
mkdir -p "$EVID"
LOG="$EVID/evidence.log"
: > "$LOG"

TAG_COMMIT=d2a6dcb27169796c3931f81c22b90d656d32bd97
ANSWER_SHA=307c39d4ec34270cf654fb144b5c67e277777cb71ced1ab1e485b7f84187fc33
DEFS_SHA=22678cfed69588aea0f61ffa7a3a819e275dd5a685015bca4318b01a7c305ded
SBBS_SHA=ec26de45881d0d5dd8664b30fbd1c21e2d426d4609b6427aabada7210ea94655
TELNET_SHA=a07664551c62620248025e8d0398a66080d6928cf2d7f6b5af08f7b7dbd9252d
BASE=https://raw.githubusercontent.com/SynchronetBBS/sbbs/$TAG_COMMIT/src/sbbs3

pass=0; fail=0
check() { # name expected actual
	if [ "$2" = "$3" ]; then
		echo "PASS $1" | tee -a "$LOG"; pass=$((pass + 1))
	else
		echo "FAIL $1 expected=[$2] actual=[$3]" | tee -a "$LOG"; fail=$((fail + 1))
	fi
}

fetch() { # url dest expected-sha
	curl -fsSL --max-time 60 -o "$2" "$1"
	check "sha256 $(basename "$2")" "$3" "$(sha256sum "$2" | cut -d' ' -f1)"
}

echo "run $(date -u +%FT%TZ) commit=$TAG_COMMIT" | tee -a "$LOG"
fetch "$BASE/answer.cpp"    "$EVID/answer-321e.cpp"    "$ANSWER_SHA"
fetch "$BASE/sbbsdefs.h"    "$EVID/sbbsdefs-321e.h"    "$DEFS_SHA"
fetch "$BASE/sbbs.h"        "$EVID/sbbs-321e.h"        "$SBBS_SHA"
fetch "$BASE/telnet.h"      "$EVID/telnet-321e.h"      "$TELNET_SHA"

check "release VERSION 3.21" \
	'#define VERSION     "3.21"  // Version: Major.minor as 4-char string' \
	"$(grep -F '#define VERSION' "$EVID/sbbsdefs-321e.h" | head -1)"
check "release REVISION e" \
	"#define REVISION    'e'     // Revision: lowercase letter" \
	"$(grep -F '#define REVISION' "$EVID/sbbsdefs-321e.h" | head -1)"
check "TELNET_TERM_MAXLEN 40 (terminal[41])" \
	'#define TELNET_TERM_MAXLEN  40' \
	"$(grep -F '#define TELNET_TERM_MAXLEN' "$EVID/telnet-321e.h" | head -1)"

# Extract the getter statement plus its clamp from both trees and compare
# byte-for-byte. The pinned parent block is the verbatim vulnerable code
# already used by the harness; no copy logic is retyped here.
grep -A4 'CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL' "$EVID/answer-321e.cpp" > "$EVID/release-block.txt"
grep -A4 'CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL' "$LAB/pins/answer-parent.cpp" > "$EVID/parent-block.txt"
check "3.21e getter block == pinned parent block" \
	"$(sha256sum "$EVID/parent-block.txt" | cut -d' ' -f1)" \
	"$(sha256sum "$EVID/release-block.txt" | cut -d' ' -f1)"

VULN='if (cryptStatusOK(cryptGetAttributeString(ssh_session, CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, terminal, &l)) && l > 0) {'
check "no-size getter call present in 3.21e" "$VULN" \
	"$(grep -F "$VULN" "$EVID/answer-321e.cpp" | head -1 | sed 's/^[[:space:]]*//')"
check "no length-query form in 3.21e" "" \
	"$(grep -F 'CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, NULL, &l' "$EVID/answer-321e.cpp" | head -1)"

grep -A4 'char[[:space:]]\+terminal\[' "$EVID/sbbs-321e.h" | head -5 > "$EVID/release-fields.txt"
grep -A4 'char[[:space:]]\+terminal\[' "$LAB/pins/sbbs.h" | head -5 > "$EVID/parent-fields.txt"
check "3.21e adjacent fields == pinned parent" \
	"$(sha256sum "$EVID/parent-fields.txt" | cut -d' ' -f1)" \
	"$(sha256sum "$EVID/release-fields.txt" | cut -d' ' -f1)"

echo "TOTAL pass=$pass fail=$fail" | tee -a "$LOG"
echo "source-bound only: no build, no wire, no witness verdict, no rung change" | tee -a "$LOG"
[ "$fail" -eq 0 ]
