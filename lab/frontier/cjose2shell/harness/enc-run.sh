#!/bin/sh
# W197 lab-only: exercise the same real overflow with attacker-selected enc /
# CEK allocation size. Existing pinned trees, KEK and harness are unchanged.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
JANSSON="$ROOT/deps/jansson-prefix"
EVID="$HERE/evidence/enc197"
mkdir -p "$EVID"
(cd "$ROOT" && sha256sum -c PINS.sha256 >/dev/null)

for kind in vuln-plain vuln-asan fixed-plain fixed-asan; do
    case "$kind" in
        vuln-plain)  SRC="$ROOT/src/plain-gcc-vulnerable"; FLAGS="" ;;
        vuln-asan)   SRC="$ROOT/src/vulnerable"; FLAGS="-fsanitize=address" ;;
        fixed-plain) SRC="$ROOT/src/plain-gcc-fixed"; FLAGS="" ;;
        fixed-asan)  SRC="$ROOT/src/fixed"; FLAGS="-fsanitize=address" ;;
    esac
    gcc -g -O0 -fno-omit-frame-pointer -Wall $FLAGS \
        -I"$SRC/include" -I"$SRC/src" -I"$JANSSON/include" \
        "$HERE/enc-driver.c" "$SRC/src/.libs/libcjose.a" \
        "$JANSSON/lib/libjansson.a" -lcrypto -lm \
        -o "$HERE/enc-$kind"
done

: > "$EVID/summary.txt"
for kind in vuln-plain vuln-asan fixed-plain fixed-asan; do
    for enc in gcm128 gcm192 cbc256 cbc384 cbc512; do
        for scenario in safe oob8 oob16 oobbig; do
            set +e
            ASAN_OPTIONS=detect_leaks=0 "$HERE/enc-$kind" "$enc" "$scenario" \
                > "$EVID/$kind.$enc.$scenario.out" 2>&1
            rc=$?
            set -e
            line=$(grep -E 'W197 |CEK_LEN_AFTER=|DECRYPT=|PLAIN_MATCH=|ERROR: AddressSanitizer' \
                   "$EVID/$kind.$enc.$scenario.out" | tr '\n' ';' | cut -c1-300)
            printf '%s %s %s rc=%s %s\n' "$kind" "$enc" "$scenario" "$rc" "$line" \
                >> "$EVID/summary.txt"
        done
    done
done
printf 'W197_RUN_DONE cases=80\n'
cat "$EVID/summary.txt"
