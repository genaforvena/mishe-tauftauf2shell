#!/bin/sh
# One-command replay of the real AIFF-C lane from a clean git archive, given
# the already-provisioned deps/ tree (SDL3 3.4.0 build + SDL_mixer 3.2.4
# sources; gitignored, provisioned locally, no network required).
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
L=$(cd "$HERE/../.." && pwd)
D="$L/deps"
E="$HERE/evidence"
mkdir -p "$E"

cd "$HERE"
sha256sum -c REAL.sha256
python3 craft_aiff.py "$E" >/dev/null
sh build-real.sh > "$E/build-real.log" 2>&1

for k in vuln-asan fixed-asan vuln-nossp; do
    case "$k" in
        vuln-asan)  s=$D/SDL_mixer-vuln-src;       b=$D/mixer-aiff-vuln-asan-build/libSDL3_mixer.a;  san=-fsanitize=address ;;
        fixed-asan) s=$D/SDL_mixer-aiff-fixed-src; b=$D/mixer-aiff-fixed-asan-build/libSDL3_mixer.a; san=-fsanitize=address ;;
        vuln-nossp) s=$D/SDL_mixer-vuln-src;       b=$D/mixer-aiff-vuln-nossp-build/libSDL3_mixer.a; san= ;;
    esac
    clang -g -O0 -fno-omit-frame-pointer $san \
        -I"$s/include" -I"$D/SDL-release-3.4.0/include" \
        -I"$D/SDL3-3.4.0-build/include-revision" \
        "$L/harness/realwav/realwav_driver.c" "$b" \
        -L"$D/SDL3-3.4.0-build" -lSDL3 -Wl,-rpath,"$D/SDL3-3.4.0-build" \
        -lm -lpthread -ldl -o "$E/aiff-driver-$k"
done

sh check-real.sh
