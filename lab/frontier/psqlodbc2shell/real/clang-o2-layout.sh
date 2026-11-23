#!/bin/sh
# W159/W160: one optimized real-object layout. Builds the pinned vulnerable
# tag with clang -O2 and sweeps the argument count to the first crash, then
# runs the fixed tag at the same layout as a control. All paths are lab-local;
# the source worktrees are provisioned by replay.sh.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB=$(CDPATH= cd -- "$HERE/.." && pwd)
REPO="$LAB/src/repo"
B="$REPO/build"
CFG=clang-o2-vuln
CFG_FIXED=clang-o2-fixed
CFLAGS='-g -O2 -fno-omit-frame-pointer -fno-stack-protector'

if [ ! -e "$B/vuln-src/.git" ]; then
  git -C "$REPO" worktree add --detach "$B/vuln-src" REL-18_00_0005 >/dev/null
fi
if [ ! -x "$B/vuln-src/configure" ]; then
  (cd "$B/vuln-src" && ./bootstrap >"$B/vuln-bootstrap.log" 2>&1)
fi
mkdir -p "$B/$CFG" "$B/evidence"
(cd "$B/$CFG" && CC=clang "$B/vuln-src/configure" \
    --with-unixodbc=__without_odbc_config \
    CFLAGS="$CFLAGS" >"$B/$CFG-configure.log" 2>&1 \
  && make -j4 >"$B/$CFG-make.log" 2>&1)
clang -DHAVE_CONFIG_H -DUNICODE_SUPPORT -I"$B/$CFG" -I"$B/vuln-src" \
    -I/usr/include -I/usr/include/postgresql -I/usr/include/postgresql/internal \
    $CFLAGS -c "$HERE/real-driver.c" -o "$B/real-driver-$CFG.o"
clang -o "$B/real-$CFG" "$B/real-driver-$CFG.o" \
    "$B/$CFG"/.libs/psqlodbcw_la-*.o -lpq -lodbcinst -lpthread

# W160: same layout and harness against the fixed tag, to control the
# n=74/80 SIGSEGV observed on the vulnerable tag in W159.
if [ ! -e "$B/fixed-src/.git" ]; then
  git -C "$REPO" worktree add --detach "$B/fixed-src" REL-18_00_0006 >/dev/null
fi
if [ ! -x "$B/fixed-src/configure" ]; then
  (cd "$B/fixed-src" && ./bootstrap >"$B/fixed-bootstrap.log" 2>&1)
fi
mkdir -p "$B/$CFG_FIXED" "$B/evidence"
(cd "$B/$CFG_FIXED" && CC=clang "$B/fixed-src/configure" \
    --with-unixodbc=__without_odbc_config \
    CFLAGS="$CFLAGS" >"$B/$CFG_FIXED-configure.log" 2>&1 \
  && make -j4 >"$B/$CFG_FIXED-make.log" 2>&1)
clang -DHAVE_CONFIG_H -DUNICODE_SUPPORT -I"$B/$CFG_FIXED" -I"$B/fixed-src" \
    -I/usr/include -I/usr/include/postgresql -I/usr/include/postgresql/internal \
    $CFLAGS -c "$HERE/real-driver.c" -o "$B/real-driver-$CFG_FIXED.o"
clang -o "$B/real-$CFG_FIXED" "$B/real-driver-$CFG_FIXED.o" \
    "$B/$CFG_FIXED"/.libs/psqlodbcw_la-*.o -lpq -lodbcinst -lpthread

for n in 16 74 80; do
  args=$(printf '1,%.0s' $(seq 1 $n))
  out="$B/evidence/w160-clang-o2-fixed-n$n.out"
  set +e
  "$B/real-$CFG_FIXED" "{fn CONCAT(${args%,})}" >"$out" 2>&1
  rc=$?
  set -e
  line=$(grep -m1 -E 'RC=|Segmentation fault|stack smashing' "$out" | cut -c1-110 || true)
  [ -n "$line" ] || line="no RC line (shell rc=$rc)"
  printf 'fixed n=%-3d rc=%-4d %s\n' "$n" "$rc" "$line"
done

for n in 73 74 80; do
  args=$(printf '1,%.0s' $(seq 1 $n))
  out="$B/evidence/w159-clang-o2-n$n.out"
  set +e
  ASAN_OPTIONS=detect_leaks=0 "$B/real-$CFG" "{fn CONCAT(${args%,})}" >"$out" 2>&1
  rc=$?
  set -e
  line=$(grep -m1 -E 'Segmentation fault|RC=|stack smashing' "$out" | cut -c1-90 || true)
  [ -n "$line" ] || line="SIGSEGV (shell rc=$rc, no stdout line)"
  printf 'n=%-3d rc=%-4d %s\n' "$n" "$rc" "$line"
done
