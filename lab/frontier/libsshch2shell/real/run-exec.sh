#!/bin/sh
# W4 follow-on: the wire-chosen callback pointer invokes a lab trampoline and
# the wire-carried command string runs in the real libssh server process.
# Rung-5 MECHANICS only: POST-AUTH (PR:L), lab-only detach/fake callback and
# in-harness trampoline; NOT ESTABLISHED without independent witness replay.
# Command is local: touch a file in this lab directory. No external traffic.
set -u
cd "$(dirname "$0")" || exit 1

V=libssh-mirror-a540e27659b08828ef61f2910a790f7cf2af9f8d
F=libssh-mirror-7dfabb1fd213196c4912c314b418ff36c882ea54
M=evidence-wire-vuln-groom-exec.marker

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

rm -f "$M"
ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=0 timeout 20 \
    ./real_wire-vuln ./hostkey groom-exec \
    >evidence-wire-vuln-groom-exec.out 2>&1
s=evidence-wire-vuln-groom-exec.out
check exec-wire-command "$(grep -q 'CLIENT sent exec cmd=touch evidence-wire-vuln-groom-exec.marker fn=0x' "$s" &&
    grep -q 'SERVER EXEC trampoline cmd=touch evidence-wire-vuln-groom-exec.marker' "$s" && echo yes)"
check exec-side-effect "$([ -f "$M" ] && echo yes)"
check exec-return "$(grep -q 'SERVER EXEC rc=0' "$s" && echo yes)"
check exec-counter-write "$(grep -q 'SERVER target_after=0x41414141414141c1' "$s" && echo yes)"
check exec-no-asan "$([ "$(grep -c 'ERROR: AddressSanitizer' "$s")" -eq 0 ] && echo yes)"
check exec-clean-exit "$(grep -q 'CLIENT rc=0 SERVER status=0x0' "$s" && echo yes)"
mv -f "$M" evidence-wire-exec-sideeffect.kept

rm -f "$M"
ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=0 timeout 20 \
    ./real_wire-fixed ./hostkey groom-exec \
    >evidence-wire-fixed-groom-exec.out 2>&1
f=evidence-wire-fixed-groom-exec.out
check fixed-exec-suppressed "$([ "$(grep -c 'SERVER data #2' "$f")" -eq 0 ] &&
    [ "$(grep -c 'SERVER EXEC trampoline' "$f")" -eq 0 ] &&
    [ ! -f "$M" ] &&
    [ "$(grep -c 'ERROR: AddressSanitizer' "$f")" -eq 0 ] &&
    grep -q 'SERVER target_after=0x4141414141414141' "$f" && echo yes)"

rm -f "$M"
ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=0 timeout 20 \
    ./real_wire-vuln ./hostkey groom-call \
    >evidence-wire-vuln-groom-call-safe.out 2>&1
c=evidence-wire-vuln-groom-call-safe.out
check safe-marker-only "$([ "$(grep -c 'SERVER EXEC trampoline' "$c")" -eq 0 ] &&
    [ ! -f "$M" ] &&
    grep -q 'SERVER MARKER called len=' "$c" && echo yes)"

echo "RESULT $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
