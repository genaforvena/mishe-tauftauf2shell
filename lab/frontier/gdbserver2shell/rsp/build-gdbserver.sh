#!/bin/bash
# Provision and build the pinned upstream gdbserver twice: vulnerable HEAD
# 633ae02c4ea8f87c670f7192804349860cfa291d and the same tree with the
# saved 2026-11-16 fix hunk. Read-only fetch plus local builds only.
set -eu
ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
SRC="$ROOT/lab/src/binutils-gdb-633ae02"
BUILD="$ROOT/lab/build/gdbserver-633ae02-asan"
FIXPATCH="$ROOT/lab/frontier/gdbserver2shell/src/fix-head-633ae02.patch"
PIN=633ae02c4ea8f87c670f7192804349860cfa291d

if [ ! -d "$SRC/.git" ]; then
  git clone --depth 1 --single-branch https://sourceware.org/git/binutils-gdb.git "$SRC"
fi
[ "$(git -C "$SRC" rev-parse HEAD)" = "$PIN" ] || {
  echo "UNEXPECTED_PIN $(git -C "$SRC" rev-parse HEAD)" >&2; exit 1;
}
mkdir -p "$BUILD"
if [ ! -f "$BUILD/Makefile" ]; then
  (cd "$BUILD" && CFLAGS='-g -O1 -fno-omit-frame-pointer -fsanitize=address' \
    CXXFLAGS='-g -O1 -fno-omit-frame-pointer -fsanitize=address' \
    LDFLAGS='-fsanitize=address' \
    "$SRC/configure" --disable-gdb --enable-gdbserver --disable-werror \
    --disable-nls --disable-libdecnumber --disable-readline --disable-sim \
    --disable-tui --disable-gdbtk --without-python --without-python3 \
    >configure.log 2>&1)
fi
(cd "$BUILD" && make -j2 all-gdbserver >build.log 2>&1)

# Fixed control: apply patch, rebuild, save binary, reverse patch, restore
# the vulnerable binary. The source tree is clean at the end either way.
(cd "$SRC" && patch -p1 --silent < "$FIXPATCH")
(cd "$BUILD" && make -j2 all-gdbserver >build-fixed.log 2>&1 \
  && cp gdbserver/gdbserver gdbserver/gdbserver-fixed)
(cd "$SRC" && patch -R -p1 --silent < "$FIXPATCH")
(cd "$BUILD" && make -j2 all-gdbserver >build-restore.log 2>&1)
[ -z "$(git -C "$SRC" status --porcelain)" ] || {
  echo "SOURCE_TREE_DIRTY" >&2; exit 1;
}
echo "VULN=$BUILD/gdbserver/gdbserver"
echo "FIXED=$BUILD/gdbserver/gdbserver-fixed"
