#!/bin/sh
# One-command clean-tree replay of every cicap2shell author lane.
#
# Usage:
#   sh replay-all.sh [WORKDIR]              # WORKDIR defaults to /tmp/cicap-replay-all
#   CICAP_TARBALL=/path/to/C_ICAP_0.6.5.tar.gz sh replay-all.sh /tmp/your-dir
#
# The tarball is fetched from the pinned codeload tag only when CICAP_TARBALL
# is unset; fetching is provisioning, and every request the script sends goes
# to 127.0.0.1 on a port this script started. All builds and raw output live
# under WORKDIR and the lane's gitignored evidence/ directory.
# A terminal line "REPLAY_ALL_OK n PASS / 0 FAIL" means every assertion below
# held on binaries this script built itself.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${1:-/tmp/cicap-replay-all}
case "$WORK" in /tmp/*) ;; *) echo "REFUSE WORKDIR outside /tmp: $WORK"; exit 2;; esac
TARBALL_SHA=6ac51b6dd39690a6ccc62e807f065e92131498687d4201a69ae9570b68bab1e5
PASS=0
FAIL=0
ok()   { printf 'PASS %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf 'FAIL %s\n' "$1"; FAIL=$((FAIL + 1)); }
need() { if grep -q "$3" "$2"; then ok "$1"; else bad "$1"; fi; }
none() { if grep -q "$3" "$2"; then bad "$1"; else ok "$1"; fi; }
die()  { printf 'SETUP_FAIL %s\n' "$1"; exit 1; }
rc0()  { if [ "$(cat "$2")" -eq 0 ]; then ok "$1"; else bad "$1"; fi; }
rcnz() { if [ "$(cat "$2")" -ne 0 ]; then ok "$1"; else bad "$1"; fi; }

rm -rf "$WORK"
mkdir -p "$WORK/bin"
T=$WORK/C_ICAP_0.6.5.tar.gz
if [ -n "${CICAP_TARBALL:-}" ]; then
    cp "$CICAP_TARBALL" "$T" || die "copy CICAP_TARBALL"
else
    curl -sSL -o "$T" \
      https://codeload.github.com/c-icap/c-icap-server/tar.gz/refs/tags/C_ICAP_0.6.5 \
      || die "fetch pinned tarball"
fi
ACT=$(sha256sum "$T" | cut -d' ' -f1)
[ "$ACT" = "$TARBALL_SHA" ] || die "tarball sha256 $ACT"
ok "tarball sha256 pinned"

tar xzf "$T" -C "$WORK" || die "unpack tarball"
SRC=$WORK/c-icap-server-C_ICAP_0.6.5
for pair in "request_common.c request_common.c" "header.c header.c" \
            "request.h include/request.h" "header.h include/header.h"; do
    set -- $pair
    a=$(sha256sum "$SRC/$2" | cut -d' ' -f1)
    b=$(sha256sum "$HERE/pinned/$1" | cut -d' ' -f1)
    [ "$a" = "$b" ] && ok "pinned $1 sha256" || die "pinned $1 sha256 $a"
done

(cd "$SRC" && autoreconf -i) > "$WORK/autoreconf.log" 2>&1 || die "autoreconf"
cp -a "$SRC" "$WORK/src-fixed"
(cd "$WORK/src-fixed" && patch -p1 < "$HERE/realbuild/fixed-release.patch") \
    > "$WORK/fixed-patch.log" 2>&1 || die "release-context fixed patch"

build() {
    name=$1
    src=$2
    san=$3
    mkdir -p "$WORK/build-$name"
    if [ "$san" = yes ]; then
        (cd "$WORK/build-$name" && \
          CFLAGS='-O0 -g -fsanitize=address -fno-omit-frame-pointer' \
          LDFLAGS='-fsanitize=address' "$src/configure") \
          > "$WORK/configure-$name.log" 2>&1 || die "configure $name"
    else
        (cd "$WORK/build-$name" && \
          CFLAGS='-O0 -g -fno-omit-frame-pointer' "$src/configure") \
          > "$WORK/configure-$name.log" 2>&1 || die "configure $name"
    fi
    (cd "$WORK/build-$name" && make -j4) > "$WORK/make-$name.log" 2>&1 \
        || die "make $name"
    ok "build $name"
}
build asan "$SRC" yes
build fixed "$WORK/src-fixed" yes
build plain "$SRC" no

link_harness() {
    out=$1
    src=$2
    builddir=$3
    san=$4
    inc="-I $SRC/include -I $builddir/include"
    if [ "$san" = yes ]; then
        gcc -std=gnu11 -O0 -g -fsanitize=address -fno-omit-frame-pointer $inc \
          "$HERE/realbuild/$src.c" -o "$WORK/bin/$out" \
          -L "$builddir/.libs" -licapapi -Wl,-rpath,"$builddir/.libs" \
          || die "link $out"
    else
        gcc -std=gnu11 -O0 -g -fno-omit-frame-pointer $inc \
          "$HERE/realbuild/$src.c" -o "$WORK/bin/$out" \
          -L "$builddir/.libs" -licapapi -Wl,-rpath,"$builddir/.libs" \
          || die "link $out"
    fi
}
link_harness real_api_asan real_api_harness "$WORK/build-asan" yes
link_harness real_api_fixed real_api_harness "$WORK/build-fixed" yes
link_harness real_api_plain real_api_harness "$WORK/build-plain" no
link_harness wire_api_asan wire_api_harness "$WORK/build-asan" yes
link_harness wire_api_fixed wire_api_harness "$WORK/build-fixed" yes
ok "five harnesses linked against locally built libicapapi"

# Pinned-function lane (the already-witnessed W205 scope) is included so the
# whole claim is replayable from one clean archive.
(cd "$HERE" && sh run.sh) > "$WORK/out-pinned.txt" 2>&1
need "pinned 19 PASS / 0 FAIL" "$WORK/out-pinned.txt" "TOTAL 19 PASS / 0 FAIL"

runbin() {
    label=$1
    shift
    "$@" > "$WORK/out-$label.txt" 2>&1
    printf '%s\n' "$?" > "$WORK/rc-$label"
}

# W1: exported functions on a real ci_request_t in the real ASan library.
for v in 90 72 4242; do
    runbin "w1-$v" "$WORK/bin/real_api_asan" attack "$v"
    need "W1 v=$v chosen alias value" "$WORK/out-w1-$v.txt" \
        "alias=1 trash0_type=2 trash0_start=$v"
    need "W1 v=$v ASan UAF" "$WORK/out-w1-$v.txt" \
        "ERROR: AddressSanitizer: heap-use-after-free"
    need "W1 v=$v pinned frame" "$WORK/out-w1-$v.txt" "header.c:631"
    rcnz "W1 v=$v nonzero rc" "$WORK/rc-w1-$v"
done
runbin w1-safe "$WORK/bin/real_api_asan" safe x
need "W1 safe alias=0" "$WORK/out-w1-safe.txt" "alias=0"
none "W1 safe no ASan" "$WORK/out-w1-safe.txt" "ERROR: AddressSanitizer"
rc0 "W1 safe rc 0" "$WORK/rc-w1-safe"
runbin w1-fixed "$WORK/bin/real_api_fixed" attack 90
need "W1 fixed alias=0" "$WORK/out-w1-fixed.txt" "alias=0"
none "W1 fixed no ASan" "$WORK/out-w1-fixed.txt" "ERROR: AddressSanitizer"
rc0 "W1 fixed rc 0" "$WORK/rc-w1-fixed"

# W2: complete ICAP bytes from an AF_UNIX socketpair.
for v in 90 4242; do
    runbin "w2-$v" "$WORK/bin/wire_api_asan" attack "$v"
    need "W2 v=$v unpack" "$WORK/out-w2-$v.txt" "unpack=0"
    need "W2 v=$v chosen alias value" "$WORK/out-w2-$v.txt" \
        "alias=1 trash0_type=2 trash0_start=$v"
    need "W2 v=$v ASan UAF" "$WORK/out-w2-$v.txt" \
        "ERROR: AddressSanitizer: heap-use-after-free"
    rcnz "W2 v=$v nonzero rc" "$WORK/rc-w2-$v"
done
runbin w2-safe "$WORK/bin/wire_api_asan" safe x
need "W2 safe alias=0" "$WORK/out-w2-safe.txt" "alias=0"
rc0 "W2 safe rc 0" "$WORK/rc-w2-safe"
runbin w2-fixed "$WORK/bin/wire_api_fixed" attack 90
need "W2 fixed alias=0" "$WORK/out-w2-fixed.txt" "alias=0"
rc0 "W2 fixed rc 0" "$WORK/rc-w2-fixed"

# W3: real server, loopback only, full parse_header/process_request path.
LIVE=$HERE/realbuild/live
live() {
    label=$1
    port=$2
    build=$3
    mode=$4
    value=$5
    realloc=$6
    sh "$LIVE/run.sh" "$build" "$port" "$label" "$mode" "$value" "$realloc" \
        > "$WORK/out-w3-$label.txt" 2>&1
}
live reqmod90 13740 "$WORK/build-asan" attack 90 100
need "W3 reqmod 400" "$WORK/out-w3-reqmod90.txt" "400 Bad request"
need "W3 reqmod ASAN=YES" "$WORK/out-w3-reqmod90.txt" "ASAN=YES"
need "W3 reqmod pinned frame" "$HERE/realbuild/evidence/live-reqmod90-server.out" "header.c:631"
live reqmod4242 13741 "$WORK/build-asan" attack 4242 100
need "W3 reqmod 4242 ASAN=YES" "$WORK/out-w3-reqmod4242.txt" "ASAN=YES"
live options 13742 "$WORK/build-asan" options 4242 100
need "W3 OPTIONS 200 OK" "$WORK/out-w3-options.txt" "200 OK"
need "W3 OPTIONS ASAN=YES" "$WORK/out-w3-options.txt" "ASAN=YES"
live safe 13743 "$WORK/build-asan" safe x 100
need "W3 safe ASAN=NO" "$WORK/out-w3-safe.txt" "ASAN=NO"
live valid 13744 "$WORK/build-asan" valid x 100
need "W3 valid 200 OK" "$WORK/out-w3-valid.txt" "200 OK"
need "W3 valid ASAN=NO" "$WORK/out-w3-valid.txt" "ASAN=NO"
live fixedreqmod 13745 "$WORK/build-fixed" attack 90 100
need "W3 fixed ASAN=NO" "$WORK/out-w3-fixedreqmod.txt" "ASAN=NO"
live fixedoptions 13746 "$WORK/build-fixed" options 4242 100
need "W3 fixed OPTIONS ASAN=NO" "$WORK/out-w3-fixedoptions.txt" "ASAN=NO"

# W4: gdb observer prints the live aliased slot inside the unmodified server.
observe() {
    label=$1
    port=$2
    build=$3
    mode=$4
    value=$5
    line=$6
    sh "$LIVE/observe.sh" "$build" "$port" "$label" "$mode" "$value" "$line" 0 \
        > "$WORK/out-w4-$label.txt" 2>&1
}
observe opt4242 13750 "$WORK/build-asan" options 4242 513
need "W4 4242 hit" "$WORK/out-w4-opt4242.txt" "W4_HIT"
need "W4 4242 start in aliased slot" "$WORK/out-w4-opt4242.txt" \
    "e5_start=4242 e5_type=2 t0_start=4242 t0_type=2 alias=1"
need "W4 4242 200 OK" "$WORK/out-w4-opt4242.txt" "200 OK"
need "W4 4242 ASAN=YES" "$WORK/out-w4-opt4242.txt" "ASAN=YES"
observe opt90 13751 "$WORK/build-asan" options 90 513
need "W4 90 start in aliased slot" "$WORK/out-w4-opt90.txt" \
    "e5_start=90 e5_type=2 t0_start=90 t0_type=2 alias=1"
observe safe 13752 "$WORK/build-asan" safe x 513
need "W4 safe no alias" "$WORK/out-w4-safe.txt" "e5=(nil) t0=(nil)"
none "W4 safe no ASan" "$WORK/out-w4-safe.txt" "ASAN=YES"
observe fixed 13753 "$WORK/build-fixed" options 4242 515
need "W4 fixed no alias" "$WORK/out-w4-fixed.txt" "e5=(nil) t0=(nil)"
none "W4 fixed no ASan" "$WORK/out-w4-fixed.txt" "ASAN=YES"

# W6: plain glibc consumer negative (print-only gdb probes).
runbin w6-plain-90 "$WORK/bin/real_api_plain" attack 90
rcnz "W6 plain rc 139" "$WORK/rc-w6-plain-90"
runbin w6-plain-safe "$WORK/bin/real_api_plain" safe x
rc0 "W6 plain safe rc 0" "$WORK/rc-w6-plain-safe"
for v in 90 72 4242; do
    gdb -q -batch -x "$HERE/realbuild/consumer_probe.gdb" \
      --args "$WORK/bin/real_api_plain" attack "$v" \
      > "$WORK/out-w6-probe-$v.txt" 2>&1
    need "W6 v=$v call 6 chosen start" "$WORK/out-w6-probe-$v.txt" \
        "W6_DESTROY n=6 .* type=2 start=$v entity=(nil)"
    need "W6 v=$v call 7 overwritten metadata" "$WORK/out-w6-probe-$v.txt" \
        "W6_DESTROY n=7 e=0x"
    need "W6 v=$v glibc metadata fields" "$WORK/out-w6-probe-$v.txt" \
        "type=21840 start=42031"
done
gdb -q -batch -x "$HERE/realbuild/malloc_window.gdb" \
  --args "$WORK/bin/real_api_plain" attack 90 \
  > "$WORK/out-w6-malloc-window.txt" 2>&1
none "W6 zero mallocs between destroy 6 and 7" \
    "$WORK/out-w6-malloc-window.txt" "W6_MALLOC_IN_WINDOW"

if [ "$FAIL" -eq 0 ]; then
    printf 'REPLAY_ALL_OK %s PASS / 0 FAIL\n' "$PASS"
else
    printf 'REPLAY_ALL_FAIL %s PASS / %s FAIL\n' "$PASS" "$FAIL"
fi
[ "$FAIL" -eq 0 ]
