#!/bin/sh
# Rebuild the pinned lwIP 2.2.1 MQTT rx_buffer overrun harness from committed
# artifacts only. No network, no source checkout, no prebuilt binaries.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PINS=$ROOT/pins
CFG=$ROOT/config
RUNS=$ROOT/runs
mkdir -p "$RUNS"

extract_pin() {
    pin=$1                      # vuln | fixed
    tgz=$PINS/lwip-2.2.1-$pin.tar.gz
    dst=$RUNS/$pin-src
    if [ -d "$dst" ]; then return; fi
    mkdir -p "$dst"
    tar -xzf "$tgz" -C "$dst"
}

build_one() {
    # build_one PIN CC MODE HARNESS_C
    pin=$1; cc=$2; mode=$3; harness=$4
    d=$RUNS/$pin-$cc-$mode
    mkdir -p "$d/harness"
    cp "$PINS/$harness" "$d/harness/mqtt_repro.c"
    ln -sfn "../$pin-src" "$d/source"
    case "$mode" in
        bounds|bounds-safe) flags="-fsanitize=bounds -fno-sanitize-recover=all" ;;
        asan)    flags="-fsanitize=address -fno-omit-frame-pointer" ;;
        plain|canary-ff|canary-80|canary-fixed) flags="-O2 -g" ;;
        *)       echo "unknown mode $mode" >&2; exit 2 ;;
    esac
    # -g -O1 everywhere keeps the raw mqtt.c:862 sink line stable.
    $cc $flags -fno-omit-frame-pointer -g -O1 \
        -I"$CFG" -I"$RUNS/$pin-src/src/include" -I"$RUNS/$pin-src/src" \
        -o "$d/harness/mqtt_repro" \
        "$d/harness/mqtt_repro.c" "$CFG/randstub.c" "$CFG/lwip_stubs.c" \
        >"$d/build.log" 2>&1
    echo "BUILD_OK $pin $cc $mode"
}

extract_pin vuln
extract_pin fixed

for cc in gcc clang; do
    build_one vuln  "$cc" bounds mqtt_repro.c
    build_one fixed "$cc" bounds mqtt_repro.c
done
build_one vuln gcc asan  mqtt_repro.c
build_one vuln clang asan mqtt_repro.c
build_one vuln gcc bounds-safe mqtt_repro_safe.c
# Safe-input control: same vulnerable pin, 128-byte (fits rx_buffer) input.
# Plain (no sanitizer) state differential.
build_one vuln gcc plain mqtt_repro.c
build_one fixed gcc plain mqtt_repro.c
build_one vuln gcc canary-ff mqtt_canary.c
build_one vuln gcc canary-80 mqtt_canary80.c
build_one fixed gcc canary-fixed mqtt_canary.c
echo "BUILD_ALL_OK"
