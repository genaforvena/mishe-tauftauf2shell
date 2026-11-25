#!/bin/sh
# mcuboot2shell one-command replay of the W8 clean-groom lane from a clean
# archive. The provisioned upstream-parent tree is gitignored, so point
# M2S_UPSTREAM at a local copy (the wrapper symlinks it into the archive):
#
#   mkdir -p /tmp/m2s-replay
#   git archive HEAD lab/frontier/mcuboot2shell | tar x -C /tmp/m2s-replay
#   M2S_UPSTREAM=/abs/path/to/lab/frontier/mcuboot2shell/upstream-parent \
#     sh /tmp/m2s-replay/lab/frontier/mcuboot2shell/replay-frontier.sh
#
# Runs serial-clean.sh (nogroom parent + fixed controls) and clean-layout.py,
# then asserts the expected rc rows and OOB/in-bounds markers. Summary goes to
# evidence/replay/summary.txt; exit 0 only when every assertion passes.
set -u
HERE=$(cd "$(dirname "$0")" && pwd -P) || exit 1
cd "$HERE" || exit 1

UP=${M2S_UPSTREAM:-}
if [ -z "$UP" ]; then
    UP=$(cd ../../upstream-parent 2>/dev/null && pwd -P) || {
        echo "M2S_UPSTREAM must name the provisioned upstream-parent tree" >&2
        exit 2
    }
fi
UP=$(cd "$UP" && pwd -P) || exit 2
if [ ! -e upstream-parent ]; then
    ln -s "$UP" upstream-parent || exit 1
fi

mkdir -p evidence/replay
SUMMARY=evidence/replay/summary.txt
: >"$SUMMARY"
overall=0

ok()   { printf 'OK   %-26s %s\n' "$1" "$2" | tee -a "$SUMMARY"; }
fail() { printf 'FAIL %-26s %s\n' "$1" "$2" | tee -a "$SUMMARY"; overall=1; }

expect_text() {
    name=$1 file=$2 pattern=$3
    if grep -q "$pattern" "$file" 2>/dev/null; then
        ok "$name" "matched $pattern"
    else
        fail "$name" "missing $pattern in $file"
    fi
}

expect_rc() {
    name=$1 log=$2 want=$3
    got=$(awk '/^hdr_size=/{split($0,a,"SERVER_RC="); print a[2]; exit}' "$log" 2>/dev/null || true)
    if [ "$got" = "$want" ]; then
        ok "$name" "SERVER_RC=$got"
    else
        fail "$name" "want SERVER_RC=$want, got ${got:-none}"
    fi
}

E=real/smp/evidence
CLEAN_OK=0
if sh real/smp/serial-clean.sh >evidence/replay/serial-clean.out 2>&1; then
    CLEAN_OK=1
    expect_text clean-run evidence/replay/serial-clean.out CLEAN_RUN_DONE
else
    fail clean-run "serial-clean.sh exited non-zero (see evidence/replay/serial-clean.out)"
fi

if [ "$CLEAN_OK" -eq 1 ]; then
    expect_rc parent-4104  "$E/clean-smp-serial-nogroom-4104.log" 139
    expect_rc parent-2048  "$E/clean-smp-serial-nogroom-2048.log" 0
    expect_rc parent-5000  "$E/clean-smp-serial-nogroom-5000.log" 139
    expect_rc parent-6000  "$E/clean-smp-serial-nogroom-6000.log" 139
    expect_rc parent-7000  "$E/clean-smp-serial-nogroom-7000.log" 0
    expect_rc fixed-4104   "$E/clean-smp-serial-fixed-4104.log" 0
    expect_text parent-oob "$E/clean-smp-serial-nogroom-4104.log" 'dst_delta=4104'
    expect_text fixed-inb  "$E/clean-smp-serial-fixed-4104.log" 'dst_delta=8'
fi

if sh -c 'cd real/smp && python3 clean-layout.py 4104' >evidence/replay/clean-layout.out 2>&1; then
    expect_text layout-done evidence/replay/clean-layout.out CLEAN_LAYOUT_DONE
    expect_text layout-magic "$E/clean-layout.txt" 96f3b83d
else
    fail layout-done "clean-layout.py exited non-zero (see evidence/replay/clean-layout.out)"
fi

printf 'REPLAY_FRONTIER_%s\n' "$([ "$overall" -eq 0 ] && echo OK || echo FAIL)" | tee -a "$SUMMARY"
exit "$overall"
