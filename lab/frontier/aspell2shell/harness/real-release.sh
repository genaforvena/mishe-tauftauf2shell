#!/bin/bash
# Build the actual prog/prezip.c from released Aspell 0.60.8.2 / 0.60.8.3
# tarballs under ASan and drive the crafted/safe streams through prezip-bin.
# The tarballs are provisioning artifacts in ../real-build/ (gitignored);
# fetch them from ftp.gnu.org if absent. No network probe beyond provisioning.
set -eu
cd "$(dirname "$0")/../real-build"

fetch() {
  local v=$1 f="aspell-${1}.tar.gz" want=$2
  if [ ! -f "$f" ]; then
    curl -fsSL -O "https://ftp.gnu.org/gnu/aspell/${f}"
  fi
  echo "$(sha256sum "$f" | cut -d' ' -f1)  $f"
  test "$(sha256sum "$f" | cut -d' ' -f1)" = "$want"
}
fetch 0.60.8.2 57fe4863eae6048f72245a8575b44b718fb85ca14b9f8c0afc41b254dfd76919
fetch 0.60.8.3 0534eae11132405120d11e46bf595bd5dd189bc124ba77a5dd6aae861b48a162

mkdir -p evidence
for v in 0.60.8.2 0.60.8.3; do
  [ -d "aspell-$v" ] || tar xzf "aspell-$v.tar.gz"
  # Verify the release source matches the committed verbatim pins.
  want=prezip.fixed.c; [ "$v" = 0.60.8.2 ] && want=prezip.vuln.c
  cmp "../pins/$want" "aspell-$v/prog/prezip.c"
  (cd "aspell-$v" && clang -fsanitize=address -fno-omit-frame-pointer -g -O1 \
     -I. prog/prezip.c -o "prezip-bin-asan-$v")
done

for v in 0.60.8.2 0.60.8.3; do
  b="aspell-$v/prezip-bin-asan-$v"
  for mode in crafted safe; do
    f=../harness/evidence/crafted.bin
    [ "$mode" = safe ] && f=../harness/evidence/crafted-clean.bin
    set +e
    ASAN_OPTIONS=detect_leaks=0 "$b" -d < "$f" \
      > "evidence/${v}-${mode}.stdout" 2> "evidence/${v}-${mode}.err"
    rc=$?
    set -e
    echo "== $v $mode rc=$rc =="
    grep -E 'ERROR: AddressSanitizer|READ of size|prezip.c:|corrupt|SUMMARY:' \
      "evidence/${v}-${mode}.err" | head -8 || true
    echo "stdout: $(head -c 80 "evidence/${v}-${mode}.stdout")"
  done
done
