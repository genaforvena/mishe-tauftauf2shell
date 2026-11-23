#!/bin/sh
# Deterministic assertions over the evidence produced by run.sh.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
E="$HERE/evidence"
p=0; f=0
ck() { # description command...
    d=$1; shift
    if "$@" >/dev/null 2>&1; then p=$((p+1)); printf 'PASS %s\n' "$d"
    else f=$((f+1)); printf 'FAIL %s\n' "$d"; fi
}
has() { grep -qF "$2" "$1"; }

ck "vuln source pin" has "$E/../../PINS.sha256" "27fc049b34ee48d65fc8eec49e1982ac0bfb3dbaf621feb31a0f74cad91175b1"
ck "fixed source pin" has "$E/../../PINS.sha256" "1925343228dedccf17254207a56e354dfef808107614c09b67028c3067f5d762"
ck "vuln extract slice pin" has "$E/../../PINS.sha256" "f74ebf4317aaae7af25fa0b3f87b239400d93681dbfdd536bf59aa6ee4c8e359"
ck "fixed extract slice pin" has "$E/../../PINS.sha256" "829403b94f6b21d937034448f8a58f57faf773febcbb4caf58494d4b3b28c149"
ck "vuln params slice pin" has "$E/../../PINS.sha256" "b027b49186c17c381c818d96974584356d75b2389cbb36830c7072c63e2926e5"
ck "fixed params slice pin" has "$E/../../PINS.sha256" "f471bca5cbeaa334576b12d439ce4dd990af9a920a05b10ac10dc3fdb09e8de1"

for cc in gcc clang; do
    for v in vuln fixed; do
        ck "$cc $v build clean" test ! -s "$E/build-$cc-$v-asan.log"
        ck "$cc $v plain build clean" test ! -s "$E/build-$cc-$v-plain.log"
    done
    ck "$cc vuln fn ASan WRITE-8 at pinned :5637" sh -c "grep -qF 'WRITE of size 8' '$E/run-$cc-vuln-asan-fn.err' && grep -qF 'convert.c.vuln:5637' '$E/run-$cc-vuln-asan-fn.err'"
    ck "$cc vuln extract ASan WRITE-1 at pinned :2424" sh -c "grep -qF 'WRITE of size 1' '$E/run-$cc-vuln-asan-extract.err' && grep -qF 'convert.c.vuln:2424' '$E/run-$cc-vuln-asan-extract.err'"
    ck "$cc vuln fn exits nonzero under ASan" sh -c "grep -qF '$cc-vuln-asan RC=1/1' '$E/rc.txt'"
    ck "$cc fixed fn rejects >16 args" has "$E/run-$cc-fixed-asan-fn.out" "too many parameters in the escape function call"
    ck "$cc fixed extract clean" has "$E/run-$cc-fixed-asan-extract.out" "EXTRACT_ASAN RETVAL=0 BUF127=00"
    ck "$cc fixed plain sink untouched" has "$E/run-$cc-fixed-plain.out" "CHOSEN_5A=0"
    ck "$cc vuln plain chosen bytes in sink" has "$E/run-$cc-vuln-plain.out" "CHOSEN_5A=112"
    ck "$cc vuln plain first diff at sink offset 0" has "$E/run-$cc-vuln-plain.out" "FIRST_DIFF=0"
    ck "$cc vuln plain chosen 5a byte dump" has "$E/run-$cc-vuln-plain.out" "SINK=215a5a5a5a5a5a5a21"
done
ck "ASan reports contain no PID in trace" sh -c "! grep -qE '[0-9]{4,}' '$E/trace.txt'"
ck "trace hash file non-empty" test -s "$E/trace.sha256"

printf 'PASS=%d FAIL=%d\n' "$p" "$f"
[ "$f" -eq 0 ]
