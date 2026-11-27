#!/bin/sh
# Build the pinned 7-Zip LZX decoders (26.05 vulnerable, 26.06 fixed) as
# standalone ASan and plain harness binaries. No upstream source is edited.
set -eu
cd "$(dirname "$0")"
(cd pins && sha256sum -c SHA256SUMS)

for pin in vuln fixed; do
  if [ ! -d "src-$pin/7zip-26.0" ]; then
    mkdir -p "src-$pin"
    tar xzf "pins/$pin.tar.gz" -C "src-$pin"
  fi
done

for pin in vuln fixed; do
  root="src-$pin/7zip-26.0$( [ "$pin" = fixed ] && echo 6 || echo 5 )"
  inc="-I$root/CPP -I$root/CPP/7zip/Compress -I$root/C -I$root"
  for mode in asan plain; do
    if [ "$mode" = asan ]; then
      flags="-fsanitize=address -fno-omit-frame-pointer -O1 -g"
    else
      flags="-O1 -g"
    fi
    gcc -std=c11 $flags $inc -c "$root/C/Alloc.c" -o "alloc-$pin-$mode.o"
    # shellcheck disable=SC2086
    g++ -std=c++11 $flags $inc harness.cpp "$root/CPP/7zip/Compress/LzxDecoder.cpp" \
      "alloc-$pin-$mode.o" -o "harness-$pin-$mode"
  done
done
echo BUILD_OK
