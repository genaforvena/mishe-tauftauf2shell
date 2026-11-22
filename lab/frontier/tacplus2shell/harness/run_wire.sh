#!/usr/bin/env bash
# Real-daemon wire cases on a plant-started 127.0.0.1 listener.
set -u
cd "$(dirname "$0")"
H=$(pwd)
R=$(dirname "$H")
V="$R/src/build/linux-6.8.0-149-generic-x86_64/tac_plus-ng/tac_plus-ng"
F="$R/src/fixed/build/linux-6.8.0-149-generic-x86_64/tac_plus-ng/tac_plus-ng"
FAIL=0

norm() {
    sed -E \
      -e 's/==[0-9]+==/==PID==/g' \
      -e 's/0x[0-9a-fA-F]+/0xADDR/g' \
      -e 's/BuildId: [0-9a-f]+/BuildId: ID/g' \
      -e 's#/home/[^ ]+/lab/frontier/tacplus2shell#ROOT#g' \
      -e 's/^==PID==ABORTING/ABORTING/' "$1"
}

hashline() {
    local label="$1" file="$2" line
    line=$(norm "$file" | sha256sum | cut -d' ' -f1)
    echo "$label $line"
}

emit() {
    local label="$1" file="$2" pattern="$3"
    if norm "$file" | grep -qE "$pattern"; then
        echo "PASS $label"
    else
        echo "FAIL $label (pattern /$pattern/ absent)"
    fi
    hashline "$label" "$file"
}

echo "=== vuln pin + crafted AUTHOR packet ==="
python3 "$H/run_case.py" --bin "$V" --log "$H/w-vuln.log" --port 4949 > "$H/w-vuln.stdout" 2>&1
cat "$H/w-vuln.stdout"
emit vuln_asan "$H/w-vuln.log" 'ERROR: AddressSanitizer: heap-buffer-overflow'
emit vuln_frame "$H/w-vuln.log" 'eval_args .*author.c:75'
emit vuln_region "$H/w-vuln.log" '243 bytes after 323-byte region'
grep 'daemon_alive_at_trigger' "$H/w-vuln.stdout"

echo "=== fixed pin + same packet ==="
python3 "$H/run_case.py" --bin "$F" --log "$H/w-fixed.log" --port 4950 > "$H/w-fixed.stdout" 2>&1
cat "$H/w-fixed.stdout"
if norm "$H/w-fixed.log" | grep -q 'AddressSanitizer'; then
    echo "FAIL fixed_no_asan"; FAIL=$((FAIL + 1))
else
    echo "PASS fixed_no_asan"
fi
hashline fixed_log "$H/w-fixed.log"
grep -q 'daemon_rc=0' "$H/w-fixed.stdout" && echo "PASS fixed_daemon_alive" || { echo "FAIL fixed_daemon_alive"; FAIL=$((FAIL+1)); }

echo "=== vuln pin + safe packet (table sums to payload) ==="
python3 "$H/run_case.py" --bin "$V" --log "$H/w-safe.log" --port 4951 --arg0 4 --rest 0 --data 'cmd=' > "$H/w-safe.stdout" 2>&1
cat "$H/w-safe.stdout"
if norm "$H/w-safe.log" | grep -q 'AddressSanitizer'; then
    echo "FAIL safe_no_asan"; FAIL=$((FAIL + 1))
else
    echo "PASS safe_no_asan"
fi
hashline safe_log "$H/w-safe.log"
grep -q 'daemon_rc=0' "$H/w-safe.stdout" && echo "PASS safe_daemon_alive" || { echo "FAIL safe_daemon_alive"; FAIL=$((FAIL+1)); }

echo "FAILURES=$FAIL"
exit "$FAIL"
