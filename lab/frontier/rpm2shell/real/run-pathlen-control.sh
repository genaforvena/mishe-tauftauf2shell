#!/usr/bin/env bash
# W310 causal control for the non-PIE GC layout divergence.
#
# Build the pinned vulnerable parent twice from the same source and deps:
# once through a /tmp tree whose absolute path lengths are identical to this
# checkout's tree, and once through a short /tmp tree. Only the embedded
# absolute path strings (and therefore static layout) differ. Replay the
# unchanged run-nopie-target.sh against each binary under normal ASLR and
# compare the live liblua GC assertions. No source or harness byte changes.
#
# Usage: bash real/run-pathlen-control.sh
# Optional: R2S_W310_REPEATS=N (default 2), R2S_W310_OUT=DIR,
# R2S_W310_MATCHED_ROOT=/tmp/..., R2S_W310_SHORT_ROOT=/tmp/...
set -u
cd "$(dirname "$0")"
lane=$PWD
root=$(cd .. && pwd)
out=${R2S_W310_OUT:-$lane/pathlen-control}
repeats=${R2S_W310_REPEATS:-2}
mkdir -p "$out"

die() { echo "REFUSE: $*" >&2; exit 1; }
[ -d "$root/src/rpm" ] || die "pinned source tree missing"
[ -d "$root/deps/root" ] || die "provisioned deps missing"
[ -x "$root/build-fixed-asan/tools/rpm" ] || die "fixed ASan control missing"
case "$repeats" in ''|*[!0-9]*) die "R2S_W310_REPEATS must be an integer";; esac
[ "$repeats" -ge 1 ] || die "R2S_W310_REPEATS must be >= 1"

# The matched tree has the same absolute path length for every path CMake
# embeds: build dir, source tree, deps prefix and install prefix.
matched=${R2S_W310_MATCHED_ROOT:-}
if [ -z "$matched" ]; then
    matched=$(python3 - "$root" <<'PY' || exit 1
import sys
root = sys.argv[1]
want = len(root + '/build-vuln-nopie') - len('/build-vuln-nopie')
prefix = '/tmp/r2s-w310-matched-'
if want < len(prefix) + 1:
    sys.exit('checkout path too short for the matched-path control')
print(prefix + 'x' * (want - len(prefix)))
PY
    ) || exit 1
fi
short=${R2S_W310_SHORT_ROOT:-/tmp/r2s-w310-short}

build_one() {
    local tree=$1 name=$2 bin
    mkdir -p "$tree/src" "$tree/deps"
    [ -e "$tree/src/rpm" ] || ln -s "$root/src/rpm" "$tree/src/rpm" || die "source symlink failed"
    [ -e "$tree/deps/root" ] || ln -s "$root/deps/root" "$tree/deps/root" || die "deps symlink failed"
    bin=$tree/build-vuln-nopie/tools/rpm
    if [ ! -x "$bin" ]; then
        export PKG_CONFIG_PATH="$tree/deps/root/usr/lib/x86_64-linux-gnu/pkgconfig:$tree/deps/root/usr/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
        cmake -S "$tree/src/rpm" -B "$tree/build-vuln-nopie" -G Ninja \
            -DCMAKE_BUILD_TYPE=Debug -DCMAKE_PREFIX_PATH="$tree/deps/root" \
            -DWITH_SEQUOIA=OFF -DWITH_OPENSSL=ON -DWITH_ACL=OFF -DWITH_AUDIT=OFF \
            -DMAGIC_LIBRARY="$tree/deps/root/usr/lib/x86_64-linux-gnu/libmagic.so" \
            -DMAGIC_INCLUDE_DIR="$tree/deps/root/usr/include" \
            -DSCDOC="$tree/deps/root/usr/bin/scdoc" \
            -DWITH_CAP=OFF -DWITH_DBUS=OFF -DWITH_FAPOLICYD=OFF \
            -DWITH_LIBDW=OFF -DWITH_LIBELF=OFF -DWITH_READLINE=OFF \
            -DWITH_SELINUX=OFF -DENABLE_PYTHON=OFF -DENABLE_PLUGINS=OFF \
            -DENABLE_NLS=OFF -DENABLE_OPENMP=OFF -DENABLE_SQLITE=OFF \
            -DENABLE_BDB_RO=OFF -DENABLE_ASAN=OFF \
            -DCMAKE_INSTALL_PREFIX="$tree/install-nopie" \
            -DCMAKE_C_FLAGS=-fno-pie -DCMAKE_CXX_FLAGS=-fno-pie \
            -DCMAKE_EXE_LINKER_FLAGS=-no-pie \
            > "$out/configure-$name.log" 2>&1 || {
                echo "FAIL $name configure"; return 1; }
        cmake --build "$tree/build-vuln-nopie" -j4 \
            > "$out/build-$name.log" 2>&1 || {
                echo "FAIL $name build"; return 1; }
    fi
    file "$bin" | grep -q 'ELF 64-bit LSB executable' || { echo "FAIL $name not non-PIE"; return 1; }
    nm "$bin" | grep -q ' rpmQVKArgs@LIBRPM_6.2$' || { echo "FAIL $name chosen symbol absent"; return 1; }
    echo "$bin"
}

matched_bin=$(build_one "$matched" matched) || exit 1
short_bin=$(build_one "$short" short) || exit 1

replay() {
    local name=$1 bin=$2 i log summary pass fail rc
    for ((i = 1; i <= repeats; i++)); do
        log="$out/run-$name-$i.log"
        RPM2SHELL_NOPIE_BIN="$bin" bash "$lane/run-nopie-target.sh" \
            > "$log" 2>&1
        rc=$?
        summary=$(grep '^NOPIE_TARGET_PASS=' "$log" | tail -1)
        pass=${summary#NOPIE_TARGET_PASS=}; pass=${pass%% *}
        fail=${summary##*NOPIE_TARGET_FAIL=}
        cp "$lane/nopie/gdb-bss.log" "$out/gdb-$name-$i.log"
        echo "$name run $i rc=$rc $summary"
        case "$name" in
            matched) [ "$rc" -eq 0 ] && [ "$fail" -eq 0 ] || return 1;;
            short)   [ "$rc" -ne 0 ] || return 1;;
        esac
    done
}

pass=0
fail=0
if replay matched "$matched_bin"; then
    echo "PASS matched-path fresh build replays the live GC dereference"
    pass=$((pass + 1))
else
    echo "FAIL matched-path fresh build did not replay"
    fail=$((fail + 1))
fi
if replay short "$short_bin"; then
    echo "PASS short-path fresh build diverges"
    pass=$((pass + 1))
else
    echo "FAIL short-path fresh build did not diverge"
    fail=$((fail + 1))
fi
echo "PATHLEN_CONTROL_PASS=$pass PATHLEN_CONTROL_FAIL=$fail"
[ "$fail" -eq 0 ]
