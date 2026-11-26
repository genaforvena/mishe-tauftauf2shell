#!/bin/sh
# Local-only reproduction: verbatim pinned Axis2/C wrapper + guththila parser.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VULN="$HERE/src/axis-axis2-c-core-584ce5bd3c98"
FIXED="$HERE/src/axis-axis2-c-core-f01683ec10e8fddb87279ec9351b3239021223e6"
CC=${CC:-gcc}
FLAG=${FLAG:--fsanitize=address -fno-omit-frame-pointer -g -O1}
XML=${XML:-'<!ENTITY x "y"><a/>'}
mkdir -p "$HERE/build"

build_and_run()
{
    name=$1; root=$2
    inc="-I $HERE/harness -I $root/util/include -I $root/util/include/platforms/unix -I $root/guththila/include -I $root/axiom/include -I $root/include"
    mkdir -p "$HERE/build/$name"
    echo "== BUILD $name =="
    $CC $FLAG $inc -o "$HERE/build/$name/driver" \
        "$HERE/harness/driver.c" \
        "$root/axiom/src/parser/guththila/guththila_xml_reader_wrapper.c" \
        "$root"/guththila/src/*.c "$root"/util/src/*.c "$root"/util/src/platforms/unix/*.c \
        -lpthread -ldl -lm 2>"$HERE/build/$name/build.log" || {
            echo "BUILD FAIL $name"; return 1; }
    echo "== RUN $name input=$XML =="
    ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
        "$HERE/build/$name/driver" "$XML" 2>&1 | tee "$HERE/build/$name/run.log"
    echo "RC $name=${PIPESTATUS:-0}"
}

build_and_run vuln "$VULN"
build_and_run fixed "$FIXED"
