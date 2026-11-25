#!/bin/sh
# Plain (non-ASan) replay of the W4 mechanics against the same pinned libssh
# commits. This removes the ASan quarantine_size_mb=0 lab condition: in an
# ordinary Release build glibc tcache naturally recycles the freed 128-byte
# channel object. The committed harness is UNMODIFIED; asan-shim/ supplies a
# no-op __asan_set_death_callback so the same source links without the ASan
# runtime (that callback only prints extra diagnostics on an ASan death).
# All traffic stays on 127.0.0.1; fetches below are source provisioning only.
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
build_plain "$VS" build-plain-vuln && build_plain "$FS" build-plain-fixed || exit 1

for kind in vuln fixed; do
    src=$VS; b=build-plain-vuln
    [ "$kind" = fixed ] && { src=$FS; b=build-plain-fixed; }
    clang -std=gnu99 -O1 -g -fno-omit-frame-pointer -Iasan-shim \
        -I "$b/src" -I "$src/src" -I "$src/include" -I "$b/include" -I "$b" \
        real_wire.c "$b/src/libssh.a" -lcrypto -lpthread -ldl \
        -o "real_wire-plain-$kind" || exit 1
    ldd "real_wire-plain-$kind" | grep -qi asan && {
        echo "FAIL-$kind links the ASan runtime"; exit 1;
    }
done

if [ ! -f hostkey ]; then
    ssh-keygen -q -t ed25519 -N '' -f hostkey </dev/null >/dev/null 2>&1 || exit 1
fi

PASS=0; FAIL=0
check() {
    # name, output file, mode (vuln|fixed), want_marker, want_exec, want_file
    c_name=$1; c_out=$2; c_mode=$3; c_wm=$4; c_we=$5; c_wf=$6
    c_data2=$(grep -c 'SERVER data #2' "$c_out")
    c_target=$(grep -c 'SERVER target_after=0x41414141414141c1' "$c_out")
    c_marker=$(grep -c 'SERVER MARKER called' "$c_out")
    c_exec=$(grep -c 'SERVER EXEC trampoline' "$c_out")
    c_file=no
    [ -f "plain-run/$c_name/evidence-wire-vuln-groom-exec.marker" ] && c_file=yes
    if [ "$c_mode" = vuln ]; then c_wd=1; c_wt=1; else c_wd=0; c_wt=0; fi
    if [ "$c_data2" = "$c_wd" ] && [ "$c_target" = "$c_wt" ] &&
       [ "$c_marker" = "$c_wm" ] && [ "$c_exec" = "$c_we" ] &&
       [ "$c_file" = "$c_wf" ]; then
        PASS=$((PASS+1)); echo "PASS-$c_name data2=$c_data2 target=$c_target marker=$c_marker exec=$c_exec file=$c_file"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$c_name got[$c_data2 $c_target $c_marker $c_exec $c_file] want[$c_wd $c_wt $c_wm $c_we $c_wf]"
    fi
}

run_lane() {
    # name, binary kind, mode
    r_name=$1; r_kind=$2; r_mode=$3
    mkdir -p "plain-run/$r_name"
    ln -sf "$HERE/hostkey" "plain-run/$r_name/hostkey"
    (cd "plain-run/$r_name" && timeout 25 \
        "$HERE/real_wire-plain-$r_kind" ./hostkey "$r_mode") \
        >"evidence-plain-$r_name.out" 2>&1
}

for mode in groom-survive groom-call groom-exec; do
    for kind in vuln fixed; do
        name="$kind-$mode"
        run_lane "$name" "$kind" "$mode"
        case "$kind:$mode" in
            vuln:groom-survive) check "$name" "evidence-plain-$name.out" vuln 0 0 no ;;
            vuln:groom-call)    check "$name" "evidence-plain-$name.out" vuln 1 0 no ;;
            vuln:groom-exec)    check "$name" "evidence-plain-$name.out" vuln 0 1 yes ;;
            *)                  check "$name" "evidence-plain-$name.out" fixed 0 0 no ;;
        esac
    done
done

# Determinism: three independent plain vulnerable groom-survive runs.
for i in 1 2 3; do
    name="vuln-survive-repeat$i"
    run_lane "$name" vuln groom-survive
    if grep -q 'SERVER target_after=0x41414141414141c1' "evidence-plain-$name.out"; then
        PASS=$((PASS+1)); echo "PASS-$name target_write=yes"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$name target_write=no"
    fi
done

echo "plain: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
