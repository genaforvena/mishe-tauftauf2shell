#!/usr/bin/env bash
# Replay driver: bash lab/frontier/kamailio2shell/run.sh <outdir>
set -u

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-out}
mkdir -p "$out"
out=$(cd "$out" && pwd)

fail=0
pass() { printf 'PASS %s\n' "$1"; }
bad()  { printf 'FAIL %s\n' "$1"; fail=1; }
need() { if grep -qF -- "$2" "$1"; then pass "$3"; else bad "$3"; fi; }

# --- pinned source bytes (fetched from the tags/commit recorded in PROVENANCE.md) ---
cat >"$out/pinned.sha256" <<'EOF'
4c845f297cb7f2ef8f8b9979c589f23724f7bfcf27708ddc72b589994e442059  notify.c.6.1.4
9dee618a7fe265ae8adc8df207f51427bf5b48a479d5159f4916d6d1f387e867  save.c.6.1.4
fafbea2d7f15ddbfa075ef06fb7fda3f0c59b4d71951a72bd0bad8081963e413  fix-21261436492f.patch
60018c6519f94ba9e69a0323c72ea6df2bcf721b7c5dd656f4f202d3b03e3eda  notify.c.6.1.5
EOF
if (cd "$here/src" && sha256sum -c "$out/pinned.sha256" >"$out/pinned.check" 2>&1); then
	pass PINNED_SOURCE_HASHES
else
	bad PINNED_SOURCE_HASHES
	cat "$out/pinned.check"
fi

# --- compile three modes ---
gcc -std=gnu11 -O0 -g -Wall -Wextra -o "$out/vuln" "$here/alias_overflow.c" || exit 91
gcc -std=gnu11 -O0 -g -Wall -Wextra -DASAN_MODE -fsanitize=address -o "$out/asan" "$here/alias_overflow.c" || exit 92
gcc -std=gnu11 -O0 -g -Wall -Wextra -DFIXED -o "$out/fixed" "$here/alias_overflow.c" || exit 93
pass COMPILE

# --- rungs 1/2/4 in the instrumented extracted harness ---
"$out/vuln" >"$out/vuln.out" 2>&1
vrc=$?
if [ "$vrc" -eq 0 ]; then pass VULN_RC0; else bad VULN_RC0; fi
need "$out/vuln.out" 'RUNG1_5DIGIT_NUL_OOB: PASS' RUNG1
need "$out/vuln.out" 'RUNG2_LEN_CAPTURED: PASS' RUNG2_LEN
need "$out/vuln.out" 'RUNG2_FNPTR_CHANGED: PASS' RUNG2_CHOSEN_FNPTR
need "$out/vuln.out" 'RUNG2_STAMP_CHANGED: PASS' RUNG2_CHOSEN_STAMP
need "$out/vuln.out" 'MARKER EXECUTED' RUNG4_MARKER
need "$out/vuln.out" 'RUNG4_MARKER_EXECUTED: PASS' RUNG4_CHECK

# --- rung 3: ASan-confirmed stack corruption ---
RUN_RUNG=3 ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$out/asan" >"$out/asan.out" 2>&1
arc=$?
if [ "$arc" -ne 0 ]; then pass ASAN_NONZERO_RC; else bad ASAN_NONZERO_RC; fi
need "$out/asan.out" 'stack-buffer-overflow' ASAN_STACK_OVERFLOW
need "$out/asan.out" 'WRITE of size' ASAN_WRITE

RUN_RUNG=fixed "$out/fixed" >"$out/fixed.out" 2>&1
frc=$?
if [ "$frc" -eq 0 ]; then pass FIXED_RC0; else bad FIXED_RC0; fi
need "$out/fixed.out" 'REJECTED len=80' FIXED_REJECTED
need "$out/fixed.out" 'FIXED_REJECTED: PASS' FIXED_REJECT_CHECK
need "$out/fixed.out" 'FIXED_NEIGHBOUR_CLEAN: PASS' FIXED_CLEAN

# --- deterministic trace (excludes ASan variable text) ---
{
	grep -E '^(RUN |PARSED |RUNG|FIXED|MARKER|DONE|REJECTED)' "$out/vuln.out" || true
	echo "ASAN_CLASS=stack-buffer-overflow"
	grep -E '^(RUN |PARSED |FIXED|REJECTED|DONE)' "$out/fixed.out" || true
} >"$out/trace.txt"
sha256sum "$out/trace.txt" | cut -d' ' -f1 >"$out/trace.sha256"
printf 'sha256=%s\n' "$(cat "$out/trace.sha256")"

if [ "$fail" -eq 0 ]; then
	echo 'ALL CHECKS PASS rc 0'
	exit 0
fi
echo 'SOME CHECKS FAILED rc 1'
exit 1
