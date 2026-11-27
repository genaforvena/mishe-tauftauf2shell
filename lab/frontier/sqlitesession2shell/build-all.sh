#!/bin/sh
# Build ASan and plain harnesses against verbatim pinned SQLite 3.53.4 and
# 3.54.0 source trees. No upstream source file is edited.
set -eu
cd "$(dirname "$0")"
(cd pins && sha256sum -c SHA256SUMS)

for pin in vuln fixed; do
  case "$pin" in
    vuln) ver=3530400 ;;
    fixed) ver=3540000 ;;
  esac
  root="src-$pin/sqlite-src-$ver"
  if [ ! -d "$root" ]; then
    mkdir -p "src-$pin"
    unzip -q "pins/$pin.zip" -d "src-$pin"
  fi
  if [ ! -f "$root/sqlite3.c" ]; then
    # Upstream release archives omit the amalgamation; generate it with the
    # pinned ./configure and mksqlite3c.tcl, as the published PoC does.
    (cd "$root" && ./configure > configure.log 2>&1 && make sqlite3.c > make.log 2>&1)
  fi
  test -f "$root/sqlite3.h"
  for mode in asan plain; do
    if [ "$mode" = asan ]; then
      flags="-O1 -g -fsanitize=address -fno-omit-frame-pointer"
    else
      flags="-O1 -g"
    fi
    # shellcheck disable=SC2086
    cc -std=c99 $flags -DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_PREUPDATE_HOOK \
      -I"$root" harness.c "$root/sqlite3.c" -o "harness-$pin-$mode" \
      -lm -lpthread -ldl
  done
done
echo BUILD_OK
