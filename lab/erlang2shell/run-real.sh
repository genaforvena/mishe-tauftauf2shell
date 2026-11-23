#!/bin/bash
# CVE-2026-55737 real-VM check on the pinned vulnerable erts build.
# Loopback only, no listener, no network, no large allocation.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE/otp-vuln"
BINDIR="$ROOT/bin/x86_64-pc-linux-gnu"
E="$HERE/evidence"
mkdir -p "$E"
rm -f "$E"/real-vm-*.out "$E"/asan.* "$E"/b2t_driver.beam

"$ROOT/bootstrap/bin/erlc" -o "$HERE" "$HERE/b2t_driver.erl" || exit 90

export ROOTDIR="$ROOT" BINDIR="$BINDIR" PROGNAME=erl

run_case() {
    name="$1"; shift
    export EMU=beam
    export ASAN_OPTIONS="detect_leaks=0:log_path=$E/${name}-asan"
    timeout 60 "$BINDIR/erlexec" "$@" -boot "$ROOT/bootstrap/bin/start" \
        -noshell -pa "$HERE" -s b2t_driver run -s init stop \
        > "$E/real-vm-$name.out" 2>&1
    printf 'MODE=%s ARGS=%s RC=%s\n' "$name" "$*" "$?"
    cat "$E/real-vm-$name.out"
}

run_case opt
run_case asan -emu_type asan -emu_flavor emu

echo '--- asan reports ---'
found=0
for f in "$E"/*-asan.*; do
    [ -f "$f" ] || continue
    found=1
    echo "### $f"
    grep -m 8 -E 'ERROR: AddressSanitizer|SUMMARY: AddressSanitizer|heap-buffer-overflow' "$f" || echo '(clean: no ASan report)'
done
[ "$found" -eq 1 ] || echo '(no ASan log files produced)'
