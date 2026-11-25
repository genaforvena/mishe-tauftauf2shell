#!/bin/sh
# socat2shell — replay the read(2) count boundary that dispositions the
# SOCKS5 sign extension as a connection abort on this host.
# No external systems: two loopback-only AF_UNIX socketpairs.
set -u
cd "$(dirname "$0")/.." || exit 2
bin=real/read-count-probe
clang -g -O1 -D_FORTIFY_SOURCE=0 -U_FORTIFY_SOURCE \
      -o "$bin" real/read_count_probe.c || exit 2
out=real/evidence-count-probe.out
./$bin > "$out" || exit 2
cat "$out"

pass=0; fail=0
ck() { if [ "$(grep -c "$2" "$out")" -eq "$3" ]; then pass=$((pass+1)); echo "PASS $1";
       else fail=$((fail+1)); echo "FAIL $1: grep [$2] count != $3"; fi; }

# Every negative-int-derived count: EFAULT, no byte stored.
ck efault-minus1   'phase=store case=minus1 .* errno=14 store=0' 1
ck efault-minus3   'phase=store case=minus3 .* errno=14 store=0' 1
ck efault-minus126 'phase=store case=minus126 .* errno=14 store=0' 1
ck efault-half     'phase=store case=half .* errno=14 store=0' 1
# Control: a large positive count is clamped by the kernel and DOES store.
ck store-2gb       'phase=store case=2gb .* errno=0 store=1' 1
# Boundary: accepted below 2^63-1, rejected above it.
ck threshold-low   'phase=threshold case=2p62 .* errno=11' 1
ck threshold-high  'phase=threshold case=maxssize .* errno=14' 1
ck threshold-bug   'phase=threshold case=minus126 .* errno=14' 1

echo "TOTAL pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
