#!/bin/sh
# Check the observed bytes, not just that a command exited.
cd "$(dirname "$0")" || exit 1
pass=0
fail=0
check() {
	if eval "$2" >/dev/null 2>&1; then
		printf 'PASS %s\n' "$1"
		pass=$((pass + 1))
	else
		printf 'FAIL %s\n' "$1"
		fail=$((fail + 1))
	fi
}
has() { grep -q "$2" "$1"; }
not() { ! grep -q "$2" "$1"; }

check 'vuln attack ASan heap WRITE' \
	"has evidence/vuln-asan-attack.out 'WRITE of size 8'"
check 'vuln attack report points at verbatim load_dsm.c:339' \
	"has evidence/vuln-asan-attack.out '/load_dsm.c:339 in DSM_Load'"
check 'vuln attack 16-byte allocation exactly overrun' \
	"has evidence/vuln-asan-attack.out '0 bytes after 16-byte region'"
check 'vuln attack16 128-byte allocation exactly overrun' \
	"has evidence/vuln-asan-attack16.out '0 bytes after 128-byte region'"
check 'vuln attack16 ASan heap WRITE' \
	"has evidence/vuln-asan-attack16.out 'WRITE of size 8'"
check 'vuln safe clean' \
	"has evidence/vuln-asan-safe.out 'channels=2 patterns=2 tracks=4 samples=1' && not evidence/vuln-asan-safe.out 'AddressSanitizer'"
check 'fixed attack rejected at header, no ASan' \
	"has evidence/fixed-asan-attack.out 'errno=9' && not evidence/fixed-asan-attack.out 'AddressSanitizer'"
check 'fixed attack16 rejected at header, no ASan' \
	"has evidence/fixed-asan-attack16.out 'errno=9' && not evidence/fixed-asan-attack16.out 'AddressSanitizer'"
check 'fixed safe clean' \
	"has evidence/fixed-asan-safe.out 'tracks=4' && not evidence/fixed-asan-safe.out 'AddressSanitizer'"
check 'vuln source has unguarded UWORD truncation' \
	"has src/mikmod-08d7d2106ce3d1d6ef1dddb060e04a10b7dc8ae2/libmikmod/loaders/load_dsm.c 'of.numtrk=of.numchn\*of.numpat;'"
check 'fixed source has product bound' \
	"has src/mikmod-a125eabbd086f311496ae46d08aaebcad0a1c426/libmikmod/loaders/load_dsm.c 'numtrk>65535'"
check 'fixed source has DSM_MAXCHAN bound' \
	"has src/mikmod-a125eabbd086f311496ae46d08aaebcad0a1c426/libmikmod/loaders/load_dsm.c 'of.numchn>DSM_MAXCHAN'"

printf 'RESULT PASS=%s FAIL=%s\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
