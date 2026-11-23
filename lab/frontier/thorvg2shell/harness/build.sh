#!/bin/sh
# Build the decoder-only harness against pinned vulnerable (v1.1.1) and fixed
# (v1.1.2) ThorVG jpgd sources with gcc and clang, ASan and plain.
set -eu
cd "$(dirname "$0")/.."
mkdir -p harness/bin

build() {
    cc="$1"; tree="$2"; san="$3"; name="$4"
    flags="-std=c++17 -g -O0 -fno-omit-frame-pointer"
    if [ "$san" = asan ]; then flags="$flags -fsanitize=address"; fi
    "$cc" $flags \
        -Iharness -Isrc/"$tree"/inc -Isrc/"$tree"/src/common -Isrc/"$tree"/src/loaders/jpg \
        harness/jpgd_asan.cpp src/"$tree"/src/loaders/jpg/tvgJpgd.cpp \
        -o harness/bin/"$name"
    echo "built harness/bin/$name ($cc $tree $san)"
}

for cc in g++ clang++; do
    tag=$(basename "$cc" | tr -d '+')
    build "$cc" vuln  asan "$tag-vuln-asan"
    build "$cc" fixed asan "$tag-fixed-asan"
    build "$cc" vuln  plain "$tag-vuln-plain"
    build "$cc" fixed plain "$tag-fixed-plain"
done
