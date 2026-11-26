#!/bin/sh
# Build and replay the OpenImageIO Cineon numberOfElements stack-overflow harness.
# No network, no OIIO library build: verbatim pinned libcineon sources plus a
# frontier-authored driver and three tiny locally generated .cin headers.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p runs

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
has() { grep -Fq -- "$2" "$1" 2>/dev/null; }

if (cd pins && sha256sum -c PIN_HASHES.txt) >runs/pins.log 2>&1; then
    ok 'all pinned upstream source and patch hashes'
else
    bad 'pinned hashes'
fi

python3 gen.py >runs/generate-files.log 2>&1 && ok 'three local .cin headers generated' \
    || bad 'generate .cin headers'
python3 gen_sink.py >runs/generate.log 2>&1 && ok 'verbatim sink slices generated' \
    || bad 'generate sinks'

python3 -c '
from pathlib import Path
v = Path("pins/vuln/cineoninput.cpp").read_text().splitlines()
f = Path("pins/fixed/cineoninput.cpp").read_text().splitlines()
sv = Path("h/sink_vuln.cpp").read_text()
sf = Path("h/sink_fixed.cpp").read_text()
for a, b in ((209, 215),):
    assert "\n".join(v[a-1:b]) in sv, ("vuln", a, b)
for a, b in ((96, 101), (246, 252)):
    assert "\n".join(f[a-1:b]) in sf, ("fixed", a, b)
assert "#line 209 \"src/cineon.imageio/cineoninput.cpp\"" in sv
assert "#line 246 \"src/cineon.imageio/cineoninput.cpp\"" in sf
print("verbatim slices and #line mappings match pinned raw lines")
' >runs/verbatim.log 2>&1 && ok 'verbatim sink slices and line mapping' \
    || bad 'verbatim sink slices'

SRC() { # pin root -> six verbatim libcineon cpp files
    for f in CineonHeader.cpp InStream.cpp Reader.cpp Codec.cpp Cineon.cpp ElementReadStream.cpp; do
        printf 'pins/%s/libcineon/%s ' "$1" "$f"
    done
}
build() { # compiler pin-root sink output
    $1 -g -O1 -fsanitize=address -std=c++17 -I "pins/$2" -I h/shim -I h \
        $(SRC "$2") h/driver.cpp "$3" -o "$4" >>runs/build.log 2>&1
}

CFLAGS_PLAIN='-g -O1 -std=c++17'
if build g++ vuln h/sink_vuln.cpp h/asan-vuln; then ok 'GCC ASan vulnerable pin built'; else bad 'GCC ASan vulnerable build'; fi
if build g++ fixed h/sink_fixed.cpp h/asan-fixed; then ok 'GCC ASan fixed pin built'; else bad 'GCC ASan fixed build'; fi
if g++ $CFLAGS_PLAIN -I pins/vuln -I h/shim -I h $(SRC vuln) h/driver.cpp h/sink_vuln.cpp -o h/plain-vuln >>runs/build.log 2>&1; then
    ok 'plain vulnerable pin built'
else
    bad 'plain vulnerable build'
fi
if command -v clang++ >/dev/null 2>&1; then
    # clang -O1 optimized the out-of-bounds store away in this pinned sink;
    # -O0 reproduces the advisory write. Preserve both observations.
    if clang++ -g -O0 -fsanitize=address -std=c++17 -I pins/vuln -I h/shim -I h \
        $(SRC vuln) h/driver.cpp h/sink_vuln.cpp -o h/clang-asan-vuln >>runs/build.log 2>&1; then
        ok 'clang -O0 ASan vulnerable pin built'
    else
        bad 'clang -O0 ASan vulnerable build'
    fi
fi

run() { # binary tag .cin-basename
    if [ -x "$1" ]; then
        "$1" "files/$3" >"runs/$2.out" 2>&1
        printf '%s\n' "$?" >"runs/$2.rc"
    fi
}

run ./h/asan-vuln    asan-vuln-attack   attack255.cin
run ./h/asan-vuln    asan-vuln-safe8    safe8.cin
run ./h/asan-vuln    asan-vuln-valid1   valid1.cin
run ./h/asan-fixed   asan-fixed-attack  attack255.cin
run ./h/asan-fixed   asan-fixed-safe8   safe8.cin
run ./h/asan-fixed   asan-fixed-valid1  valid1.cin
run ./h/plain-vuln   plain-vuln-attack  attack255.cin
if [ -x h/clang-asan-vuln ]; then
    run ./h/clang-asan-vuln clang-asan-vuln-attack attack255.cin
fi

trap_check() { # tag pinned-line
    out="runs/$1.out"
    if [ -f "$out" ] && has "$out" 'AddressSanitizer: stack-buffer-overflow' &&
       has "$out" 'WRITE of size 8' && has "$out" "'strings'" &&
       has "$out" "cineoninput.cpp:$2"; then
        ok "$1: WRITE-8 at verbatim pinned cineoninput.cpp:$2"
    else
        bad "$1: expected WRITE-8 at pinned cineoninput.cpp:$2"
    fi
}
trap_check asan-vuln-attack 215
if [ -f runs/clang-asan-vuln-attack.out ]; then trap_check clang-asan-vuln-attack 215; fi

if [ "$(cat runs/asan-fixed-attack.rc 2>/dev/null)" = '0' ] &&
   ! has runs/asan-fixed-attack.out 'AddressSanitizer:' &&
   has runs/asan-fixed-attack.out 'open_like=0'; then
    ok 'fixed pin rejects count 255 with no ASan report'
else
    bad 'fixed pin control'
fi

clean=1
for t in asan-vuln-safe8 asan-vuln-valid1 asan-fixed-safe8 asan-fixed-valid1; do
    if [ ! -f "runs/$t.rc" ] || [ "$(cat "runs/$t.rc")" != '0' ] ||
       has "runs/$t.out" 'AddressSanitizer:'; then
        clean=0
    fi
done
if [ "$clean" = 1 ]; then ok 'safe(8) and valid(1) vectors clean on both pins'; else bad 'safe/valid controls'; fi
if [ -f runs/plain-vuln-attack.rc ]; then ok 'plain vulnerable outcome recorded (no rung 1 claim)'; else bad 'plain vulnerable outcome'; fi

printf 'PASS=%s FAIL=%s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
