#!/usr/bin/env bash
# W129: live-daemon write-what-where via eval_args' `t` stack slot.
# Vulnerable: three chosen records overwrite `t` and copy a chosen payload to
# a chosen heap address; fixed pin rejects; vulnerable with no prime has no
# chosen source and performs no control write.
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

# Replace only real addresses (12+ hex digits), leaving byte values intact.
# POST12 cmdoff is a decimal pointer delta that tracks the stack/environment
# layout; mask it so the evidence hash is portable across environments.
norm() {
    sed -E -e 's/0x[0-9a-fA-F]{12,}/0xADDR/g' -e 's/cmdoff=[0-9]+/cmdoff=N/g' -e "s#$R#ROOT#g" "$1"
}

run_case() {
    local name="$1" bin="$2" libdir="$3" port="$4" extra="$5"
    python3 "$H/run_gdb2.py" --bin "$bin" --libdir "$libdir" --port "$port" \
        --log "$H/ptr-$name.log" --gdbcmd "$H/gdb-ptr.cmd" \
        --client wire5.py --client-args="$extra" \
        > "$H/ptr-$name.stdout" 2>/dev/null
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
    if grep -qaE "$pattern" "$file"; then
        echo "PASS $label"
    else
        echo "FAIL $label (pattern /$pattern/ absent)"
        FAIL=$((FAIL + 1))
    fi
}

absent_raw() {
    local label="$1" file="$2" pattern="$3"
    if grep -qaE "$pattern" "$file"; then
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
        grep -a -E '^(trigger seq|target=)' "$H/ptr-$name.stdout" || true
        # Only the pointer/control lines belong in the evidence hash. gdb stop
        # lines (^Program received) and raw x/ byte dumps vary with the
        # environment and are deliberately excluded (W132, witness #1884).
        norm "$H/ptr-$name.log" | grep -E \
          '^(EVALARGS|PRE12|POST12|PRE13|POST13|PRE14|POST14|PRE14 target_|POST14 target_)' \
          | grep -vE '^0x[0-9a-f]+:' | head -60
    }
}

# Assert the write changed the target without pinning environment-specific
# pre-write heap bytes: witness #1884 saw the local 0x50 prefill become zeros
# or a heap pointer under a 4096-byte environment filler, which spuriously
# failed the old vuln_before / vuln_nul assertions.
target_bytes() {
    awk '
      /^PRE14 target_before:/ { inb=1; buf=""; next }
      /^POST14 target_after:/ { if (inb) { print buf; inb=0 } ina=1; buf=""; next }
      /^0x[0-9a-f]+:/ { for (i=2; i<=NF; i++) buf = buf $i " "; next }
      END { if (ina) print buf }
    ' "$1"
}

changed() {
    local label="$1" file="$2" before after
    before=$(target_bytes "$file" | sed -n '1p')
    after=$(target_bytes "$file" | sed -n '2p')
    if [ -n "$before" ] && [ -n "$after" ] && [ "$before" != "$after" ]; then
        echo "PASS $label"
    else
        echo "FAIL $label (pre/post target dumps identical or absent)"
        FAIL=$((FAIL + 1))
    fi
}

written_nul() {
    local label="$1" file="$2" b16
    b16=$(target_bytes "$file" | sed -n '2p' | tr ' ' '\n' | sed -n '17p')
    if [ "$b16" = "0x00" ]; then
        echo "PASS $label"
    else
        echo "FAIL $label (no NUL after chosen payload: /$b16/)"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== vulnerable pin + chosen-address write ==="
run_case vuln "$V" "$VL" 5004 ""
emit vuln_eval "$H/ptr-vuln.log" '^EVALARGS in=0xADDR base=0xADDR inlen=104$'
emit vuln_t_slot "$H/ptr-vuln.log" '^PRE13 i=13 l=12 a=0xADDR t=0xADDR tslot=0xADDR cmdline=0xADDR$'
emit vuln_t_redirect "$H/ptr-vuln.log" '^PRE14 i=14 l=21 a=0xADDR t=0xADDR TARGET=0xADDR$'
changed vuln_target_changed "$H/ptr-vuln.log"
emit vuln_chosen_write "$H/ptr-vuln.log" '^0xADDR:(\s+0x50\s+0x57\s+0x4e\s+0x33){2}$'
written_nul vuln_written_nul "$H/ptr-vuln.log"
emit_raw vuln_heap_target "$H/ptr-vuln.log" '^PRE14 .* TARGET=0x5555'
emit vuln_reply_18 "$H/ptr-vuln.stdout" 'reply_len=18'

echo "=== fixed pin + same wire input ==="
run_case fixed "$F" "$FL" 5005 ""
absent fixed_no_eval "$H/ptr-fixed.log" '^EVALARGS '
emit fixed_reply_57 "$H/ptr-fixed.stdout" 'reply_len=57'

echo "=== vulnerable pin + no prime ==="
run_case noprime "$V" "$VL" 5006 "--no-prime"
absent_raw noprime_no_redirect "$H/ptr-noprime.log" '^PRE14 .* TARGET=0x5555'
emit_raw noprime_stack_target "$H/ptr-noprime.log" '^PRE14 .* TARGET=0x7fff'
absent noprime_no_write "$H/ptr-noprime.log" '^0xADDR:(\s+0x50\s+0x57\s+0x4e\s+0x33){2}$'
emit noprime_reply_18 "$H/ptr-noprime.stdout" 'reply_len=18'

echo "=== normalized evidence hashes ==="
for n in vuln fixed noprime; do
    printf '%s ' "$n"
    extract "$n" | sha256sum | cut -d' ' -f1
done
echo "FAILURES=$FAIL"
exit "$FAIL"
