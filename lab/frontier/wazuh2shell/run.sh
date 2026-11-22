#!/bin/sh
# Direct-call reproduction of the Wazuh FIM alert sink on hash-pinned source.
# Usage: bash run.sh OUTDIR
set -eu
OUT=${1:?outdir}
mkdir -p "$OUT/build"
extract_fn() {
    # Verbatim byte slice of one top-level function from the pinned source.
    # The trailing "{" filter excludes forward declarations ending in ";".
    awk -v pat="$2" '
        !seen && $0 ~ pat && /\{[[:space:]]*$/ { on=1; seen=1 }
        on { print }
        on && $0 == "}" { on=0; print "" }
    ' "$1"
}
for tag in v4.14.7 v4.14.8; do
    src="src/syscheck.c.$tag"
    : > "$OUT/build/extracted.$tag.inc"
    extract_fn "$src" '^size_t fim_generate_comment\\(char \\* str' >> "$OUT/build/extracted.$tag.inc"
    extract_fn "$src" '^int fim_fetch_attributes\\(cJSON \\*new_attrs' >> "$OUT/build/extracted.$tag.inc"
    extract_fn "$src" '^int fim_fetch_attributes_state\\(cJSON \\*attr' >> "$OUT/build/extracted.$tag.inc"
    extract_fn "$src" '^static int fim_generate_alert\\(Eventinfo \\*lf' >> "$OUT/build/extracted.$tag.inc"
    cp "$OUT/build/extracted.$tag.inc" extracted.inc
    extra=""
    if [ "$tag" = v4.14.8 ]; then extra="-DWZ_FIXED"; fi
    gcc -std=gnu11 -fsanitize=address -fno-omit-frame-pointer -g -O0 \
        $extra -I src -I "$OUT/build" harness.c -o "$OUT/build/harness-$tag" \
        -l:libcjson.so.1
    for mode in exploit control; do
        echo "=== $tag $mode ===" > "$OUT/$tag-$mode.log"
        ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
            "$OUT/build/harness-$tag" "$mode" >> "$OUT/$tag-$mode.log" 2>&1 || true
        cat "$OUT/$tag-$mode.log"
    done
    gcc -std=gnu11 -g -O0 -DWZ_PLAIN $extra -I src -I "$OUT/build" \
        harness.c -o "$OUT/build/harness-plain-$tag" -l:libcjson.so.1
    for mode in exploit control; do
        echo "=== plain $tag $mode ===" > "$OUT/plain-$tag-$mode.log"
        "$OUT/build/harness-plain-$tag" "$mode" >> "$OUT/plain-$tag-$mode.log" 2>&1 || true
        cat "$OUT/plain-$tag-$mode.log"
    done
done
rm -f extracted.inc
