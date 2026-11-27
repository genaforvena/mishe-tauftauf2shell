#!/bin/sh
set -eu
if [ "$#" -ne 2 ]; then
    echo "usage: sh build-reproducers.sh LIBICAL_SOURCE LIBICAL_ASAN_BUILD" >&2
    exit 2
fi
libical_repro_source=$(cd "$1" && pwd)
libical_repro_build=$(cd "$2" && pwd)
for libical_repro_file in 0*.c; do
    libical_repro_output=${libical_repro_file%.c}
    clang -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
        -I"$libical_repro_build/src" -I"$libical_repro_build/src/libical" \
        -I"$libical_repro_source/src" -I"$libical_repro_source/src/libical" \
        "$libical_repro_file" "$libical_repro_build/lib/libical.a" \
        -lm -lpthread -o "$libical_repro_output"
done
