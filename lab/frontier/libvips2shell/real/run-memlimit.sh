#!/usr/bin/env bash
# Reproduce the W8 eager-zero-fill measurement inside this wake's cgroup.
# Safe sizes only: the 1500/2048/4300 MB timeouts are recorded in PROVENANCE.md
# as a one-off observation and are deliberately not replayed here.
set -u
cd "$(dirname "$0")" || exit 1

OUT=memlimit.out
: >"$OUT"

CG=$(sed -n '1s/^0:://p' /proc/self/cgroup)
CGPATH="/sys/fs/cgroup$CG"
{
	echo "CGROUP=$CG"
	for key in memory.max memory.high memory.current; do
		echo "$key=$(cat "$CGPATH/$key" 2>/dev/null || echo UNKNOWN)"
	done
	echo "PROBE=gcc -O0 memlimit.c; posix_memalign(16,N MiB)+memset(0,N MiB)"
} >>"$OUT"

gcc -O0 -o memlimit memlimit.c || exit 1
for mb in 64 256 1024; do
	echo "--- ${mb}MB timeout 30 ---" >>"$OUT"
	timeout 30 ./memlimit "$mb" >>"$OUT" 2>&1
	echo "RC=$?" >>"$OUT"
done

fail=0
check() {
	if grep -qF "$2" "$OUT"; then
		echo "PASS $1 :: $2"
	else
		echo "FAIL $1 :: $2"
		fail=1
	fi
}
absent() {
	if grep -qF "$2" "$OUT"; then
		echo "FAIL $1 :: must not contain $2"
		fail=1
	else
		echo "PASS $1 :: absent $2"
	fi
}
check memlimit.out 'CGROUP=/user.slice/'
check memlimit.out 'memory.max='
check memlimit.out 'memory.high='
check memlimit.out 'memset 64 MB in'
check memlimit.out 'memset 256 MB in'
check memlimit.out 'memset 1024 MB in'
absent memlimit.out 'ALLOC_FAIL'
echo "RESULT fail=$fail"
exit "$fail"
