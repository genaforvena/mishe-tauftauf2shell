#!/bin/sh
# Replay the pinned TDengine trimString off-by-one: ASan class, chosen bytes in
# a real adjacent stack object, and fixed/safe controls. Loopback/local only.
set -eu
cd "$(dirname "$0")/.."
sha256sum -c SHA256SUMS >/dev/null
mkdir -p evidence raw
pass=0; fail=0
check() {
    label=$1; shift
    if "$@"; then pass=$((pass+1)); printf 'PASS %s\n' "$label";
    else fail=$((fail+1)); printf 'FAIL %s\n' "$label"; fi
}
contains() { grep -q -- "$1" "$2"; }
absent() { ! grep -q -- "$1" "$2"; }

for arm in vuln-asan-gcc vuln-asan-clang fixed-asan-gcc vuln-plain-gcc; do
    test -x "bin/$arm" || { echo "MISSING bin/$arm"; exit 1; }
done

for esc in '%' _ x; do
    tag=$(case "$esc" in '%') echo pct;; _) echo under;; x) echo xesc;; esac)
    raw="raw/vuln-$tag-gcc.log"
    ./bin/vuln-asan-gcc "$esc" Z >"$raw" 2>&1 || true
    check "asan-$tag-class" contains 'AddressSanitizer: stack-buffer-overflow' "$raw"
    check "asan-$tag-write1" contains 'WRITE of size 1' "$raw"
    check "asan-$tag-line" contains 'trimString .*parUtil.c:461' "$raw"
    grep -E 'WRITE of size 1|SUMMARY: AddressSanitizer' "$raw" | sed -E -e 's/ at 0x[0-9a-f]+//' -e 's#^SUMMARY:.*/parUtil.c:461#SUMMARY: AddressSanitizer: stack-buffer-overflow parUtil.c:461#' >"evidence/vuln-$tag-stable.out" || true

    raw="raw/vuln-$tag-clang.log"
    ./bin/vuln-asan-clang "$esc" Z >"$raw" 2>&1 || true
    check "clang-$tag-class" contains 'AddressSanitizer: stack-buffer-overflow' "$raw"
    check "clang-$tag-line" contains 'parUtil.c:461' "$raw"

    raw="raw/fixed-$tag.log"
    ./bin/fixed-asan-gcc "$esc" Z >"$raw" 2>&1 || true
    check "fixed-$tag-clean" absent 'AddressSanitizer' "$raw"
    check "fixed-$tag-n31" contains 'TRIM_N=31' "$raw"

    raw="raw/victim-$tag.log"
    ./bin/vuln-plain-gcc victim "$esc" Z >"$raw" 2>&1 || true
    byte=$(case "$esc" in '%') echo 0x25;; _) echo 0x5f;; x) echo 0x78;; esac)
    check "victim-$tag-chosen" contains "VICTIM=$byte" "$raw"
done

./bin/vuln-asan-gcc safe Z >raw/safe-vuln.log 2>&1 || true
check safe-clean absent 'AddressSanitizer' raw/safe-vuln.log
check safe-n2 contains 'TRIM_N=2' raw/safe-vuln.log
./bin/fixed-asan-gcc victim '%' Z >raw/victim-fixed.log 2>&1 || true
check fixed-victim-intact contains 'VICTIM=0x5a' raw/victim-fixed.log

grep -h -E 'WRITE of size 1|SUMMARY: AddressSanitizer' raw/vuln-pct-gcc.log | sed -E -e 's/ at 0x[0-9a-f]+//' -e 's#^SUMMARY:.*/parUtil.c:461#SUMMARY: AddressSanitizer: stack-buffer-overflow parUtil.c:461#' >evidence/vuln-summary-stable.out
grep -h 'VICTIM=' raw/victim-*.log >evidence/victim-stable.out
sha256sum -c evidence/SHA256SUMS >/dev/null 2>&1 && check evidence-pins true || check evidence-pins false

printf 'RUN_ALL_OK %d PASS / %d FAIL\n' "$pass" "$fail"
test "$fail" -eq 0
