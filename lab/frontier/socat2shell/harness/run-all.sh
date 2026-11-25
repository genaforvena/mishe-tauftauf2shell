#!/bin/sh
# socat2shell — deterministic pinned-byte replay. Rebuilds every variant from
# the pinned source blobs, verifies SHA-256 pins, and checks ASan and chosen
# byte readback outcomes. No network access.
set -u
cd "$(dirname "$0")/.." || exit 2
export LC_ALL=C

fail=0
pass=0
ck() {
	if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "PASS $1 ($2)";
	else fail=$((fail+1)); echo "FAIL $1 got=[$2] want=[$3]"; fi
}

# Re-extract the verbatim function body from the pinned release tarball.
mkdir -p src/tree
tar xzf src/socat-1.8.1.1.tar.gz -C src/tree socat-1.8.1.1/xio-socks5.c socat-1.8.1.1/xio-socks5.h
sed -n '414,499p' src/tree/socat-1.8.1.1/xio-socks5.c > src/xio-socks5.inc
cp src/tree/socat-1.8.1.1/xio-socks5.h src/xio-socks5.h.vuln
sed 's/char\tdstdata\[\]/unsigned char dstdata[]/' src/xio-socks5.h.vuln > src/xio-socks5.h.fixed
(cd src && sha256sum -c pins.sha256) || exit 2

cp src/xio-socks5.inc harness/xio-socks5.inc
CFLAGS="-O1 -g -Wall -Wextra -Wno-unused-parameter -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-stack-protector"
for kind in vuln fixed; do
	cp "src/xio-socks5.h.$kind" harness/xio-socks5.h
	(cd harness && gcc $CFLAGS -fsanitize=address -DEXACT_ALLOC -o "$kind-asan" harness.c) || exit 2
	(cd harness && gcc $CFLAGS -o "$kind-plain" harness.c) || exit 2
	(cd harness && clang $CFLAGS -fsanitize=address -DEXACT_ALLOC -o "$kind-asan-clang" harness.c) || exit 2
done

# ASan: vulnerable attack is a heap write past the 262-byte reply buffer.
out=$(cd harness && ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./vuln-asan attack 2>&1)
ck vuln-asan-write "$(printf '%s' "$out" | grep -c 'ERROR: AddressSanitizer: heap-buffer-overflow')" 1
ck vuln-asan-size "$(printf '%s' "$out" | grep -c 'WRITE of size 600')" 1
ck vuln-asan-region "$(printf '%s' "$out" | grep -c '262-byte region')" 1
ck vuln-asan-frame "$(printf '%s' "$out" | grep -c '_xioopen_socks5_read_reply')" 1
out=$(cd harness && ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./vuln-asan-clang attack 2>&1)
ck clang-asan-write "$(printf '%s' "$out" | grep -c 'ERROR: AddressSanitizer: heap-buffer-overflow')" 1

# Controls: safe reply and the official 1.8.1.2 header are ASan-clean.
for args in 'vuln-asan safe' 'fixed-asan attack' 'fixed-asan safe' 'fixed-asan-clang attack'; do
	set -- $args
	out=$(cd harness && ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./"$1" "$2" 2>&1)
	ck "clean-$1-$2" "$(printf '%s' "$out" | grep -c 'ERROR: AddressSanitizer')" 0
	ck "rc-$1-$2" "$(printf '%s' "$out" | grep -c 'rc=0')" 1
done

# Plain build: attacker-chosen bytes land at the first byte past the reply.
out=$(cd harness && ./vuln-plain attack 2>&1)
ck vuln-plain-marker "$(printf '%s' "$out" | grep -c 'canary=4d495348452d534f434b53')" 1
out=$(cd harness && ./fixed-plain attack 2>&1)
ck fixed-plain-intact "$(printf '%s' "$out" | grep -c 'canary=000000000000000000000000')" 1

echo "TOTAL pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
