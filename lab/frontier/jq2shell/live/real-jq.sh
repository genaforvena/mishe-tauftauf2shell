#!/bin/bash
# jq2shell real-jq path confirmation (2026-11-23).
#
# Rebuilds both hash-pinned jq tarballs with ASan and drives two small jq
# expressions that reach the exact upstream functions named by
# CVE-2026-32316. It records the real allocation arithmetic at the pinned
# lines under gdb, with fixed-1.8.2 controls. It does NOT reproduce the
# advisory's ~2 GiB geometries: this wake's cgroup has memory.max 2 GiB, so
# the full PoC strings cannot be allocated here. See
# reports/jq2shell-status.md for that negative result.
set -eu
cd "$(dirname "$0")/.."
ROOT=$PWD
BUILD=$ROOT/build
OUT=$ROOT/live/evidence
mkdir -p "$BUILD" "$OUT"
export LC_ALL=C
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
export LSAN_OPTIONS=detect_leaks=0

sha256sum -c PINS.sha256 > "$OUT/pins.out"

CG=/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/self/cgroup)
{
  for key in memory.max memory.high; do
    if [ -r "$CG/$key" ]; then
      echo "$key=$(cat "$CG/$key")"
    else
      echo "$key=UNKNOWN"
    fi
  done
} > "$OUT/memory-guard.out"

build() {
  ver=$1
  tree=$BUILD/jq-jq-$ver
  if [ ! -x "$tree/.libs/jq" ]; then
    tar xzf "$ROOT/src/jq-$ver.tar.gz" -C "$BUILD"
    (
      cd "$tree"
      autoreconf -i > "$OUT/autoreconf-$ver.log" 2>&1
      ./configure --enable-asan --disable-maintainer-mode \
        --with-oniguruma=/usr \
        CFLAGS='-g -O1 -fno-omit-frame-pointer' \
        > "$OUT/configure-$ver.log" 2>&1
      make -j2 > "$OUT/make-$ver.log" 2>&1
    )
  fi
  test -x "$tree/.libs/jq"
  ldd "$tree/.libs/jq" | grep -q libasan
  echo "$ver $(sha256sum "$tree/.libs/jq" | cut -d' ' -f1)" > "$OUT/jq-binary-$ver.sha256"
}

# gdb_geometries <version> <label> <source line> <jq program> <printf gdb expr>
gdb_geometries() {
  ver=$1 label=$2 line=$3 program=$4 format=$5
  tree=$BUILD/jq-jq-$ver
  cmd=$BUILD/gdb-$label.cmd
  cat > "$cmd" <<EOF
set pagination off
set breakpoint pending on
break src/jv.c:$line
commands
silent
$format
bt 4
continue
end
run -n '$program'
EOF
  (
    cd "$tree"
    LD_LIBRARY_PATH="$tree/.libs" gdb -q -batch -x "$cmd" --args ./.libs/jq
  ) > "$OUT/gdb-$label.raw" 2>&1
  grep -E '^(GEOM|#[0-9]|Breakpoint)' "$OUT/gdb-$label.raw" |
    sed -E 's/0x[0-9a-f]+/0xADDR/g; s#/[^ ]*/src/#SRC/#g' \
    > "$OUT/gdb-$label.out"
  grep -q '^GEOM' "$OUT/gdb-$label.out"
}

: > "$OUT/safe-runs.out"
: > "$OUT/geometry-summary.out"

for ver in 1.8.1 1.8.2; do
  build "$ver"
  tree=$BUILD/jq-jq-$ver
  export LD_LIBRARY_PATH="$tree/.libs"

  # Real jq process, real allocator: these small inputs reach both pinned
  # functions without needing the guard-blocked multi-gigabyte strings.
  append_len=$("$tree/.libs/jq" -n '"x" * 1000 | length')
  bad_len=$("$tree/.libs/jq" -n '"////" * 10 | @base64d | length')
  echo "$ver APPEND_LEN=$append_len BAD_LEN=$bad_len" >> "$OUT/safe-runs.out"
  test "$append_len" = 1000
  test "$bad_len" = 30

  if [ "$ver" = 1.8.1 ]; then
    gdb_geometries "$ver" append-vuln 1189 \
      '("x" * 1000) + "xx" | length' \
      'printf "GEOM APP currlen=%u len=%u allocsz=%u\n", currlen, len, (currlen+len)*2'
    gdb_geometries "$ver" bad-vuln 1118 \
      '"////" * 10 | @base64d | length' \
      'printf "GEOM BAD length=%u maxlength=%u\n", length, length*3+1'
    grep -m1 'GEOM APP currlen=1000 len=2 allocsz=2004' \
      "$OUT/gdb-append-vuln.out" >> "$OUT/geometry-summary.out"
    grep -m1 'GEOM BAD length=30 maxlength=91' \
      "$OUT/gdb-bad-vuln.out" >> "$OUT/geometry-summary.out"
  else
    gdb_geometries "$ver" append-fixed 1181 \
      '("x" * 1000) + "xx" | length' \
      'printf "GEOM APP-FIXED currlen=%u len=%u sum64=%llu\n", currlen, len, (unsigned long long)currlen + (unsigned long long)len'
    gdb_geometries "$ver" bad-fixed 1117 \
      '"////" * 10 | @base64d | length' \
      'printf "GEOM BAD-FIXED length=%u maxlength64=%llu\n", length, (unsigned long long)length * 3 + 1'
    grep -m1 'GEOM APP-FIXED currlen=1000 len=2 sum64=1002' \
      "$OUT/gdb-append-fixed.out" >> "$OUT/geometry-summary.out"
    grep -m1 'GEOM BAD-FIXED length=30 maxlength64=91' \
      "$OUT/gdb-bad-fixed.out" >> "$OUT/geometry-summary.out"
  fi
done

grep -q '^1.8.1 APPEND_LEN=1000 BAD_LEN=30$' "$OUT/safe-runs.out"
grep -q '^1.8.2 APPEND_LEN=1000 BAD_LEN=30$' "$OUT/safe-runs.out"
test "$(wc -l < "$OUT/geometry-summary.out")" = 4
cat "$OUT/geometry-summary.out"
echo REAL-JQ-PASS
