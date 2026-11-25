#!/bin/sh
# W16 one-command replay: negative-divisor limb of the pinned :1751 write.
# Needs the four locally built trees from replay-real.sh and replay-nonpie.sh.
cd "$(dirname "$0")" || exit 1
fail=0
check() {
    if [ "$2" = "$3" ]; then
        printf 'PASS %s\n' "$1"
    else
        printf 'FAIL %s: expected [%s] got [%s]\n' "$1" "$3" "$2"
        fail=$((fail+1))
    fi
}
check_ge() {
    if [ "$2" -ge "$3" ]; then
        printf 'PASS %s (>= %s)\n' "$1" "$3"
    else
        printf 'FAIL %s: expected >=%s got [%s]\n' "$1" "$3" "$2"
        fail=$((fail+1))
    fi
}

python3 make-negdiv-case.py > replay-negdiv-gen.out 2>&1 || exit 1
# All-skipped safe control: no store at all, isolates the divisor effect.
python3 - <<'PY'
from pathlib import Path
import struct
base = bytearray(Path("truncated.pcf").read_bytes()[:0x123])
struct.pack_into("<HHHH", base, 0x118, 2, 0, 65534, 0)
data = bytes(base[:0x122]) + b"\xff\xff" * 65533
Path("negdiv-safe.pcf").write_bytes(data)
Path("import-negdiv-safe.ff").write_text("New()\nImport(\"" + str(Path.cwd() / "negdiv-safe.pcf") + "\")\n")
PY

for mode in plain nopie; do
    gdb -q -batch -x gdb-negdiv.cmd "./build-$mode/bin/fontforge" \
        > "replay-negdiv-gdb-$mode.out" 2>&1 || exit 1
    check "gdb-$mode-hit" \
        "$(grep -c 'HIT glyph=-50 i=65532' "replay-negdiv-gdb-$mode.out")" 1
    check "gdb-$mode-byte3" \
        "$(grep -Ec '0xfe.*0x05.*0x01.*0xff' "replay-negdiv-gdb-$mode.out")" 1
done
check 'pie-pointer' "$(grep -c '0x00005555ff0105fe' replay-negdiv-gdb-plain.out)" 1
check 'nopie-pointer' "$(grep -c '0x00000000ff0105fe' replay-negdiv-gdb-nopie.out)" 1

for b in build-plain build-fixed-plain build-asan build-fixed build-nopie build-fixed-nopie; do
    "./$b/bin/fontforge" -script import-negdiv-safe.ff \
        > "replay-negdiv-safe-$b.out" 2>&1
    check "safe-$b" "$?" 0
done
for b in build-plain build-fixed-plain build-nopie build-fixed-nopie; do
    "./$b/bin/fontforge" -script import-negdiv-atk.ff \
        > "replay-negdiv-atk-$b.out" 2>&1
    check "atk-$b" "$?" 0
done
"./build-asan/bin/fontforge" -script import-negdiv-atk.ff \
    > replay-negdiv-atk-build-asan.out 2>&1
check 'atk-asan-rc' "$?" 1
check 'atk-asan-write4' \
    "$(grep -c 'WRITE of size 4' replay-negdiv-atk-build-asan.out)" 1
check_ge 'atk-asan-line' \
    "$(grep -c 'fvimportbdf.c:1751' replay-negdiv-atk-build-asan.out)" 1

# Byte 3 = 0xff is written, but the resulting pointer is outside every
# mapping printed by gdb in the same transcript (no mapped target).
python3 - <<'PY' > replay-negdiv-mapping.out
import re
from pathlib import Path
ok = True
for name in ("replay-negdiv-gdb-plain.out", "replay-negdiv-gdb-nopie.out"):
    txt = Path(name).read_text()
    m = re.search(r'pointer word at encs-200:\n0x[0-9a-f]+:\s+(0x[0-9a-f]+)', txt)
    addr = int(m.group(1), 16) if m else None
    segs = re.findall(r'^\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+\S+\s+\S+\s+(\S+)', txt, re.M)
    hit = [s for s in segs if addr is not None and int(s[0], 16) <= addr < int(s[1], 16)]
    print(f"{name} {addr:#x} mapped_in {hit}")
    ok &= addr is not None and not hit
print("RESULT", "UNMAPPED" if ok else "MAPPED")
PY
check 'result-unmapped' "$(grep -c 'RESULT UNMAPPED' replay-negdiv-mapping.out)" 1

if [ "$fail" -eq 0 ]; then
    printf 'REPLAY_NEGDIV_OK: 20 checks, 0 failed\n'
else
    printf 'REPLAY_NEGDIV_FAIL: %s failed\n' "$fail"
fi
exit "$fail"
