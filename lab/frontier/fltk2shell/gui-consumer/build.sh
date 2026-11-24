#!/bin/sh
# Build the GUI consumer against the already-built ASan FLTK 1.4.5 trees.
set -eu
cd "$(dirname "$0")"
ASAN_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O1'

for spec in 'vuln:../fltk-1.4.5-plus1632/build-fixed' \
            'fixed:../fltk-1.4.5-plus1647/build-fixed'; do
  label=${spec%%:*}
  cfg="${spec#*:}/fltk-config"
  printf '+ g++ %s -o gui-%s gui.cxx $($cfg --cxxflags --ldflags --use-images)\n' \
    "$ASAN_FLAGS" "$label"
  # shellcheck disable=SC2086
  g++ $ASAN_FLAGS -o "gui-$label" gui.cxx $("$cfg" --cxxflags --ldflags --use-images)
done
echo 'build OK'
