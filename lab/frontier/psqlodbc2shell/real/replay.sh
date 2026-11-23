#!/bin/sh
# Rebuild pinned psqlODBC tags from provisioned source, link real upstream
# objects against real-driver.c, and run the two bounded CVE-2026-120061
# scenarios. Lab-local only; no network, no server, no external probe.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB=$(CDPATH= cd -- "$HERE/.." && pwd)
REPO="$LAB/src/repo"
B="$REPO/build"
mkdir -p "$B"

for pair in 'vuln REL-18_00_0005' 'fixed REL-18_00_0006'; do
  set -- $pair
  v=$1; tag=$2
  if [ ! -e "$B/$v-src/.git" ]; then
    git -C "$REPO" worktree add --detach "$B/$v-src" "$tag" >/dev/null
  fi
  if [ ! -x "$B/$v-src/configure" ]; then
    (cd "$B/$v-src" && ./bootstrap >"$B/$v-bootstrap.log" 2>&1)
  fi
done

build_tree() { # cfg src cc cflags ldflags
  cfg=$1; src=$2; cc=$3; cflags=$4; ldflags=$5
  mkdir -p "$B/$cfg"
  (cd "$B/$cfg" && CC="$cc" "$B/$src/configure" \
      --with-unixodbc=__without_odbc_config \
      CFLAGS="$cflags" LDFLAGS="$ldflags" >"$B/$cfg-configure.log" 2>&1 \
    && make -j4 >"$B/$cfg-make.log" 2>&1)
  $cc -DHAVE_CONFIG_H -DUNICODE_SUPPORT -I"$B/$cfg" -I"$B/$src" \
      -I/usr/include -I/usr/include/postgresql -I/usr/include/postgresql/internal \
      $cflags -c "$HERE/real-driver.c" -o "$B/real-driver-$cfg.o"
  $cc $ldflags -o "$B/real-$cfg" "$B/real-driver-$cfg.o" \
      "$B/$cfg"/.libs/psqlodbcw_la-*.o -lpq -lodbcinst -lpthread
  echo "BUILT real-$cfg"
}

A0='-g -O0 -fno-omit-frame-pointer -fsanitize=address'
P0='-g -O0 -fno-omit-frame-pointer -fno-stack-protector'
build_tree asan-vuln vuln-src gcc "$A0" '-fsanitize=address'
build_tree asan-fixed fixed-src gcc "$A0" '-fsanitize=address'
build_tree plain-vuln vuln-src gcc "$P0" ''
build_tree plain-fixed fixed-src gcc "$P0" ''
build_tree default-vuln vuln-src gcc '-g -O2' ''
build_tree clang-vuln vuln-src clang "$P0" ''

mkdir -p "$B/evidence"
args24=$(printf '1,%.0s' $(seq 1 24))
fn24="{fn CONCAT(${args24%,})}"
body200=$(printf '1%.0s' $(seq 1 200))
date200="{d ${body200}}"
for cfg in asan-vuln asan-fixed plain-vuln plain-fixed default-vuln clang-vuln; do
  for spec in "fn24:$fn24" "date200:$date200" "safe_fn:{fn CONCAT(1,2)}"; do
    tag=${spec%%:*}; sql=${spec#*:}
    out="$B/evidence/replay-$cfg-$tag.out"
    ASAN_OPTIONS=detect_leaks=0 "$B/real-$cfg" "$sql" >"$out" 2>&1 || true
    printf '%-18s %-8s %s\n' "$cfg" "$tag" \
      "$(grep -m1 -E 'WRITE of size|stack smashing|RC=|ERROR: AddressSanitizer' "$out" | cut -c1-100)"
  done
done
