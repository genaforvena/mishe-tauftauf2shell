#!/usr/bin/env bash
# Replay driver: bash lab/frontier/uftpd2shell/run.sh <outdir>
# Extracts the VERBATIM compose_path() from the pinned upstream src/common.c at
# tags v2.15 (vulnerable) and v2.16 (fixed), pads leading lines so upstream
# line numbers are preserved, and compiles each with the same driver.  The
# function body is never reimplemented.
set -u

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-out}
mkdir -p "$out"
out=$(cd "$out" && pwd)

fail=0
pass() { printf 'PASS %s\n' "$1"; }
bad()  { printf 'FAIL %s\n' "$1"; fail=1; }
need() { if grep -qF -- "$2" "$1"; then pass "$3"; else bad "$3"; fi; }
neednot() { if grep -qF -- "$2" "$1"; then bad "$3"; else pass "$3"; fi; }

# --- pinned source bytes (fetched from the tags recorded in PROVENANCE.md) ---
cat >"$out/pinned.sha256" <<'EOF'
9efddcbc1ee9309961b71d30e241f0c0d7d8b67a8b15123fdd006f82c9f22aff  common.c.v2.15
2d63f3f9fdec49bba897c07d2799dfdaf65c9ead4ba2fd5358d49cde8426ee56  common.c.v2.16
1427fdce2eadd378716546c45fede1f76c62657780385e923bb1ef6446f545d7  fix.patch
EOF
if (cd "$here/src" && sha256sum -c "$out/pinned.sha256" >"$out/pinned.check" 2>&1); then
	pass PINNED_SOURCE_HASHES
else
	bad PINNED_SOURCE_HASHES
	cat "$out/pinned.check"
fi

# --- verbatim extraction, line numbers preserved ---
for tag in v2.15 v2.16; do
	src="$here/src/common.c.$tag"
	sig=$(grep -n '^char \*compose_path' "$src" | cut -d: -f1)
	{
		for ((i = 1; i < sig; i++)); do printf '\n'; done
		awk -v start="$sig" 'NR >= start { print } NR > start && /^}/ { exit }' "$src"
	} >"$out/common.c.$tag"
done
need "$out/common.c.v2.15" 'memmove(dir + len, dir, strlen(dir) + 1)' EXTRACT_VULN_FN
need "$out/common.c.v2.16" 'if (strlen(dir) + 1 > sizeof(dir) - len)' EXTRACT_FIXED_FN
if [ "$(grep -n 'memmove(dir + len' "$out/common.c.v2.15" | cut -d: -f1)" = "61" ]; then
	pass UPSTREAM_LINE_NUMBER_61
else
	bad UPSTREAM_LINE_NUMBER_61
fi
need "$out/common.c.v2.15" 'memcpy(dir, home, len)' UPSTREAM_MEMCPY

# --- compile real pinned function, three modes ---
CFLAGS='-std=gnu11 -O0 -g -Wall -Wextra -include '"$here/uftpd.h"
gcc $CFLAGS -fstack-protector-all -o "$out/vuln" "$here/driver.c" -x c "$out/common.c.v2.15" || exit 91
gcc $CFLAGS -fsanitize=address -o "$out/asan" "$here/driver.c" -x c "$out/common.c.v2.15" || exit 92
gcc $CFLAGS -fstack-protector-all -o "$out/fixed" "$here/driver.c" -x c "$out/common.c.v2.16" || exit 93
pass COMPILE

OVER=128

# --- rung 1/2: plain build. The 128-byte OOB memmove overwrites the stack
# canary; glibc detects it on return from the upstream function. ---
"$out/vuln" "$OVER" vuln >"$out/vuln.out" 2>&1
vrc=$?
if [ "$vrc" -ne 0 ]; then pass VULN_ABORT_NONZERO_RC; else bad VULN_ABORT_NONZERO_RC; fi
need "$out/vuln.out" 'stack smashing detected' VULN_STACK_CANARY
need "$out/vuln.out" 'expected_oob=128' VULN_TRIGGER_GEOMETRY
need "$out/vuln.out" 'chosen_marker=55465450' VULN_CHOSEN_BYTES_SUPPLIED

# --- rung 3: ASan-confirmed stack corruption in the REAL upstream function ---
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$out/asan" "$OVER" asan >"$out/asan.out" 2>&1
arc=$?
if [ "$arc" -ne 0 ]; then pass ASAN_NONZERO_RC; else bad ASAN_NONZERO_RC; fi
need "$out/asan.out" 'stack-buffer-overflow' ASAN_STACK_OVERFLOW
need "$out/asan.out" 'WRITE of size' ASAN_WRITE_SIZE
need "$out/asan.out" 'compose_path' ASAN_UPSTREAM_FRAME
need "$out/asan.out" 'common.c.v2.15:61' ASAN_UPSTREAM_CALL_SITE
need "$out/asan.out" 'overflows this variable' ASAN_EXACT_BOUNDARY
need "$out/asan.out" 'chosen_marker=55465450' RUNG4_CHOSEN_MARKER
need "$out/asan.out" 'chosen_fn=0x1122334455667788' RUNG4_CHOSEN_VALUE

# --- fixed control: 2.16 truncates dir[] before the memmove ---
"$out/fixed" "$OVER" fixed >"$out/fixed.out" 2>&1
frc=$?
if [ "$frc" -eq 0 ]; then pass FIXED_RC0; else bad FIXED_RC0; fi
neednot "$out/fixed.out" 'stack smashing detected' FIXED_NO_CANARY_ABORT
need "$out/fixed.out" 'expected_oob=128' FIXED_SAME_INPUT
need "$out/fixed.out" 'returned=' FIXED_RETURNED
need "$out/common.c.v2.16" 'if (strlen(dir) + 1 > sizeof(dir) - len)' FIXED_GUARD_PRESENT

# --- deterministic trace (excludes ASan PID/address/path text) ---
{
	grep -E '^(label=|expected_oob=|tail_path_off=|chosen_marker=|chosen_fn=|returned=)' "$out/vuln.out" || true
	grep -E '^(label=|expected_oob=|tail_path_off=|chosen_marker=|chosen_fn=|returned=)' "$out/asan.out" || true
	echo 'ASAN_CLASS=stack-buffer-overflow'
	grep -E '^(label=|expected_oob=|returned=)' "$out/fixed.out" || true
} >"$out/trace.txt"
sha256sum "$out/trace.txt" | cut -d' ' -f1 >"$out/trace.sha256"
printf 'sha256=%s\n' "$(cat "$out/trace.sha256")"

if [ "$fail" -eq 0 ]; then
	echo 'ALL CHECKS PASS rc 0'
	exit 0
fi
echo 'SOME CHECKS FAILED rc 1'
exit 1
