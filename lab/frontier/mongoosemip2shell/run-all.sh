#!/bin/sh
# Rebuild pinned Mongoose 7.23/7.24 from codeload tarballs and drive the
# MIP stack with the local mock-L2 PoC: three-way handshake, 400 bytes of
# data, then FIN carrying 400 bytes. All frames are crafted in-process.
# Read-only provisioning for sources; no external target contact.
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC=$ROOT/src
OUT=$ROOT/out
EV=$ROOT/evidence
mkdir -p "$SRC" "$OUT" "$EV"

check() {
  expected=$1; file=$2
  actual=$(sha256sum "$file" | cut -d' ' -f1)
  if [ "$actual" != "$expected" ]; then
    echo "PIN_FAIL $file expected=$expected actual=$actual"; exit 1
  fi
}

check 93208f164038b05d156935b8b725063e1afb3984a362dbcf3a9ea37b6f1f2255 "$SRC/mongoose-7.23.tar.gz"
check 0b21cc2ac2a094600d58f2bd20d42aa21ce88375adefc32af481fe89997285fb "$SRC/mongoose-7.24.tar.gz"
check 70d3b17e9a3d429c7c5c3dcbbc22c54401e9181d2518c8a453901c91c862f822 "$SRC/fix-9c6b4edd.patch"
check 50ebb930ac9fc2c84286bfa350243f243495aa1a0e38759b6a856219cfd1a6d9 "$ROOT/poc.c"

for tag in 7.23 7.24; do
  if [ ! -f "$SRC/mongoose-$tag/src/net_builtin.c" ]; then
    (cd "$SRC" && tar xzf "mongoose-$tag.tar.gz") || exit 1
  fi
done

# Plain (no-ASan) builds are deliberately excluded: on BOTH tags the harness
# crashes/hangs before the handshake in mg_timer_poll (gdb backtrace in
# evidence/plain-backtrace.txt), a harness/plain-build issue, not a control.
for tag in 7.23 7.24; do
  cc -g -O0 -fsanitize=address -DMG_IO_SIZE=512 -I"$SRC/mongoose-$tag" \
    "$ROOT/poc.c" -o "$OUT/poc-$tag-gcc-asan" || exit 1
  clang -g -O0 -fsanitize=address -DMG_IO_SIZE=512 -I"$SRC/mongoose-$tag" \
    "$ROOT/poc.c" -o "$OUT/poc-$tag-clang-asan" || exit 1

done

PASS=0; FAIL=0
report() {
  if [ "$1" = ok ]; then
    PASS=$((PASS + 1)); echo "PASS $2"
  else
    FAIL=$((FAIL + 1)); echo "FAIL $2: $3"
  fi
}

for tag in 7.23 7.24; do
  for build in gcc-asan clang-asan; do
    for mode in attack safe; do
      name="$tag-$build-$mode"
      f="$EV/$name.out"
      ASAN_OPTIONS=detect_leaks=0 "$OUT/poc-$tag-$build" "$mode" > "$f" 2>&1
      rc=$?
      case "$tag-$build-$mode" in
        7.23-*-asan-attack)
          if [ "$rc" -ne 0 ] &&
             grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$f" &&
             grep -q 'WRITE of size 400' "$f" &&
             grep -q 'read_conn' "$f" &&
             grep -q '512-byte region' "$f"; then
            report ok "$name"
          else
            report bad "$name" "rc=$rc expected ASan WRITE-400 at read_conn"
          fi
          ;;
        *)
          asan_clean=yes
          case "$build" in *asan) grep -q 'ERROR: AddressSanitizer' "$f" && asan_clean=no ;; esac
          if [ "$rc" -eq 0 ] && [ "$asan_clean" = yes ] &&
             grep -q "AFTER_FIN mode=$mode" "$f"; then
            report ok "$name"
          else
            report bad "$name" "rc=$rc asan_clean=$asan_clean"
          fi
          ;;
      esac
    done
  done
done
echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ]
