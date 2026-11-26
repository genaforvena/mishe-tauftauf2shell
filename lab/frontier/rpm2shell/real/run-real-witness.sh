#!/usr/bin/env bash
# One-command clean-archive replay of the real-rpm grade evidence for
# CVE-2026-95520. Nothing built by the author is reused: all three rpm
# binaries are compiled here from the pinned upstream git trees.
#
# Usage, from a clean `git archive <commit> lab/frontier/rpm2shell`:
#   ln -s <author-lane>/src/rpm        src/rpm
#   ln -s <author-lane>/src/rpm-fixed src/rpm-fixed
#   ln -s <author-lane>/deps/root     deps/root
#   bash real/run-real-witness.sh
#
# The symlinked prerequisites are provisioning only (upstream git objects at
# the pinned commits and extracted development headers); their commits and
# pkg-config files are checked below. GDB is required by two of the runners.
set -u
cd "$(dirname "$0")"
lane=$PWD
root=$(cd .. && pwd)

die() { echo "REFUSE: $*" >&2; exit 1; }

vuln_pin=c36e855034e604ef20863d541d44ef8c2dbac9e8
fixed_pin=5bc8705e0f9a9ffc123fb1c693bdad13de9f7c03
for pair in "src/rpm:$vuln_pin" "src/rpm-fixed:$fixed_pin"; do
    dir=${pair%%:*}
    want=${pair##*:}
    [ -f "$root/$dir/lib/rpmfi.cc" ] || die "$dir missing (see usage)"
    got=$(git -C "$root/$dir" rev-parse HEAD 2>/dev/null) || die "$dir is not a git tree"
    [ "$got" = "$want" ] || die "$dir HEAD $got, expected $want"
    echo "PIN $dir $got"
done
[ -f "$root/deps/root/usr/lib/x86_64-linux-gnu/pkgconfig/popt.pc" ] || \
    die "deps/root popt.pc missing (see usage)"

# The extracted dev packages use absolute prefixes pointing at the
# provisioning tree; PKG_CONFIG_PATH selects them (the symlink above keeps
# those prefixes valid after a clean-archive replay).
export PKG_CONFIG_PATH="$root/deps/root/usr/lib/x86_64-linux-gnu/pkgconfig:$root/deps/root/usr/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

# Canonical names are written only in a fresh archive; never overwrite an
# author build tree if this script is started from the live worktree.
for d in build-vuln-asan build-fixed-asan build-vuln-plain; do
    [ -e "$root/$d" ] && die "$root/$d exists; run from a clean archive"
done

flagset=(
    -DCMAKE_BUILD_TYPE=Debug
    -DCMAKE_PREFIX_PATH="$root/deps/root"
    -DWITH_SEQUOIA=OFF -DWITH_OPENSSL=ON -DWITH_ACL=OFF -DWITH_AUDIT=OFF
    -DMAGIC_LIBRARY="$root/deps/root/usr/lib/x86_64-linux-gnu/libmagic.so"
    -DMAGIC_INCLUDE_DIR="$root/deps/root/usr/include"
    -DSCDOC="$root/deps/root/usr/bin/scdoc"
    -DWITH_CAP=OFF -DWITH_DBUS=OFF -DWITH_FAPOLICYD=OFF -DWITH_LIBDW=OFF
    -DWITH_LIBELF=OFF -DWITH_READLINE=OFF -DWITH_SELINUX=OFF
    -DENABLE_PYTHON=OFF -DENABLE_PLUGINS=OFF -DENABLE_NLS=OFF
    -DENABLE_OPENMP=OFF -DENABLE_SQLITE=OFF -DENABLE_BDB_RO=OFF
)

build() {
    local name=$1 src=$2 asan=$3
    local b="$root/.witness-build/$name"
    echo "BUILD $name from $src (ASAN=$asan)"
    cmake -S "$root/$src" -B "$b" -G Ninja "${flagset[@]}" \
        -DENABLE_ASAN="$asan" -DCMAKE_INSTALL_PREFIX="$root/.witness-install-vuln" \
        > "$lane/witness-$name-configure.log" 2>&1 || {
            tail -n 30 "$lane/witness-$name-configure.log"; die "configure $name failed"; }
    cmake --build "$b" -j 4 > "$lane/witness-$name-build.log" 2>&1 || {
        tail -n 40 "$lane/witness-$name-build.log"; die "build $name failed"; }
    [ -x "$b/tools/rpm" ] || die "$b/tools/rpm missing"
    ln -s ".witness-build/$name" "$root/build-$name"
}

mkdir -p "$root/.witness-build"
build vuln-asan src/rpm ON
build fixed-asan src/rpm-fixed ON
build vuln-plain src/rpm OFF

cmake --install "$root/.witness-build/vuln-asan" \
    > "$lane/witness-install.log" 2>&1 || {
        tail -n 30 "$lane/witness-install.log"; die "config install failed"; }
vuln_config=$root/.witness-install-vuln/lib/rpm
[ -f "$vuln_config/rpmrc" ] || die "installed config has no rpmrc"
cfg_link=$(mktemp -d /tmp/r2s-cfg.XXXXX) || die "mktemp failed"
rmdir "$cfg_link" || die "rmdir failed"
ln -s "$vuln_config" "$cfg_link" || die "config symlink failed"
trap 'rm -f "$cfg_link"' EXIT

export RPM_CONFIGDIR_VULN="$cfg_link"
export RPM_CONFIGDIR_FIXED="$root/.witness-build/fixed-asan"

total_pass=0
total_fail=0
for runner in run-real.sh run-scaled-payload.sh run-install-consumer.sh run-gc-pointer.sh; do
    echo "=== $runner ==="
    timeout -k 5 300 bash "$runner" > "$lane/witness-$runner.log" 2>&1
    rc=$?
    nfail=$(grep -c '^FAIL ' "$lane/witness-$runner.log" || true)
    npass=$(grep -c '^PASS ' "$lane/witness-$runner.log" || true)
    echo "RUNNER $runner RC=$rc PASS=$npass FAIL=$nfail log=real/witness-$runner.log"
    total_pass=$((total_pass + npass))
    total_fail=$((total_fail + nfail))
    if [ "$rc" -ne 0 ] || [ "$nfail" -ne 0 ]; then
        tail -n 40 "$lane/witness-$runner.log"
    fi
done
echo "WITNESS_REAL_TOTAL PASS=$total_pass FAIL=$total_fail"
[ "$total_fail" -eq 0 ] || exit 1
exit 0
