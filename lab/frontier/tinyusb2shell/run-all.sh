#!/bin/sh
# Local-only reproduction: verbatim pinned TinyUSB HID parser + local driver.
# The parser function is sliced byte-for-byte from each pinned source tree.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VULN="$HERE/src/tinyusb-5014146fef1aac07362ee35c0c361b8475f7636d"
FIXED="$HERE/src/tinyusb-85047e1777f5c20b7a936aa905c746125d3ed066"
CC=${CC:-gcc}
FLAG=${FLAG:--fsanitize=address -fno-omit-frame-pointer -g -O1}
mkdir -p "$HERE/build"

build_and_run()
{
    name=$1; root=$2
    src="$root/src/class/hid/hid_host.c"
    [ -f "$src" ] || { echo "MISSING $src"; return 1; }
    d="$HERE/build/$name"
    mkdir -p "$d"
    sed -n '/^uint8_t tuh_hid_parse_report_descriptor(/,/^}/p' "$src" > "$d/parser.inc"
    echo "== BUILD $name parser_lines=$(wc -l < "$d/parser.inc") sha=$(sha256sum "$d/parser.inc" | cut -d' ' -f1) =="
    $CC $FLAG -I "$HERE/harness" -I "$d" -o "$d/driver" \
        "$HERE/harness/driver.c" 2>"$d/build.log" || {
            echo "BUILD FAIL $name"; cat "$d/build.log"; return 1; }
    for input in attack width safe; do
        echo "== RUN $name input=$input =="
        ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
            "$d/driver" "$input" >"$d/run-$input.log" 2>&1
        echo "RC $name/$input=$?"
        grep -E 'ERROR: AddressSanitizer|READ of size|WRITE of size|report_num=' "$d/run-$input.log" || true
    done
}

build_and_run vuln "$VULN"
build_and_run fixed "$FIXED"
