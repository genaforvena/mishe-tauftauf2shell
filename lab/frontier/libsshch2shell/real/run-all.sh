#!/bin/sh
# Real-build replay for CVE-2026-59850: pinned vulnerable/fixed libssh commits
# built under ASan, authenticated loopback SSH session, CHANNEL_CLOSE followed
# by CHANNEL_DATA, server app frees the channel inside its data callback.
# All traffic stays on 127.0.0.1; fetches below are source provisioning only.
set -u
cd "$(dirname "$0")" || exit 1

V=a540e27659b08828ef61f2910a790f7cf2af9f8d
F=7dfabb1fd213196c4912c314b418ff36c882ea54
VS=libssh-mirror-$V
FS=libssh-mirror-$F
CFLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O1'

provision() {
    sha=$1; dir=$2
    if [ ! -d "$dir" ]; then
        curl -fsSL --max-time 60 \
            "https://codeload.github.com/libssh/libssh-mirror/tar.gz/$sha" \
            -o "$dir.tar.gz" || return 1
        tar -xzf "$dir.tar.gz" || return 1
    fi
}

build() {
    dir=$1; out=$2
    cmake -S "$dir" -B "$out" -G Ninja \
        -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang \
        -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' \
        -DWITH_SERVER=ON -DUNIT_TESTING=OFF -DBUILD_SHARED_LIBS=OFF \
        -DWITH_GSSAPI=OFF -DWITH_ZLIB=OFF >"$out.configure.log" 2>&1 &&
    ninja -C "$out" ssh >"$out.build.log" 2>&1
}

provision "$V" "$VS" && provision "$F" "$FS" || exit 1
build "$VS" build-asan && build "$FS" build-fixed || exit 1

for kind in vuln fixed; do
    src=$VS; b=build-asan
    [ "$kind" = fixed ] && { src=$FS; b=build-fixed; }
    clang -std=gnu99 -O1 -g -fsanitize=address -fno-omit-frame-pointer \
        -I "$b/src" -I "$src/src" -I "$src/include" -I "$b/include" -I "$b" \
        real_wire.c "$b/src/libssh.a" -lcrypto -lpthread -ldl \
        -o "real_wire-$kind" || exit 1
done

if [ ! -f hostkey ]; then
    ssh-keygen -q -t ed25519 -N '' -f hostkey </dev/null >/dev/null 2>&1 || exit 1
fi

PASS=0; FAIL=0
expect() {
    # name, binary, mode, expected ASan count, expected data#2 count
    name=$1; bin=$2; mode=$3; want_asan=$4; want_data=$5
    out="evidence-wire-$name.out"
    ASAN_OPTIONS=detect_leaks=0 timeout 20 "./$bin" ./hostkey $mode >"$out" 2>&1
    got_asan=$(grep -c 'ERROR: AddressSanitizer' "$out")
    got_data=$(grep -c 'SERVER data #2' "$out")
    if [ "$got_asan" -eq "$want_asan" ] && [ "$got_data" -eq "$want_data" ]; then
        PASS=$((PASS+1)); echo "PASS-$name asan=$got_asan data2=$got_data"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$name asan=$got_asan/$want_asan data2=$got_data/$want_data"
    fi
}
expect vuln-close-data real_wire-vuln '' 1 1
expect fixed-close-data real_wire-fixed '' 0 0
expect vuln-data-only real_wire-vuln data-only 0 1
expect fixed-data-only real_wire-fixed data-only 0 1

# The vulnerable ASan report must name the pinned callback and show chosen
# wire bytes at payload offset 16 in the server data callback.
if grep -q 'channels.c:705:26 in channel_rcv_data' evidence-wire-vuln-close-data.out &&
   grep -q 'freed by thread T0 here' evidence-wire-vuln-close-data.out &&
   grep -q 'SERVER auth rc=0\|CLIENT auth rc=0' evidence-wire-vuln-close-data.out &&
   grep -q 'SERVER data #2 len=21 first=M off16=-' evidence-wire-vuln-close-data.out; then
    PASS=$((PASS+1)); echo 'PASS-wire-asan-pinned-frame-and-chosen-bytes'
else
    FAIL=$((FAIL+1)); echo 'FAIL-wire-asan-pinned-frame-and-chosen-bytes'
fi

echo "RESULT $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
