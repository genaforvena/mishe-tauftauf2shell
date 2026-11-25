#!/bin/sh
# socat2shell — real-build, loopback-only control matrix.
# Builds pinned socat 1.8.1.1 and 1.8.1.2 under clang ASan, then sends a
# malicious or safe SOCKS5 reply from a 127.0.0.1-only listener to a real
# socat SOCKS5 client. No external system is contacted.
set -u
cd "$(dirname "$0")/.." || exit 2
(cd src && sha256sum -c pins.sha256) || exit 2
mkdir -p real

for v in 1.8.1.1 1.8.1.2; do
	if [ ! -x "real/socat-$v/socat" ]; then
		tar xzf "src/socat-$v.tar.gz" -C real
		(cd "real/socat-$v" &&
		 ./configure CC=clang CFLAGS='-g -O1 -fsanitize=address -fno-omit-frame-pointer -D_FORTIFY_SOURCE=0 -U_FORTIFY_SOURCE' --disable-openssl &&
		 make -j4) > "real/build-$v.log" 2>&1 || exit 2
	fi
done

pass=0; fail=0
ck() { if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "PASS $1 ($2)";
       else fail=$((fail+1)); echo "FAIL $1 got=[$2] want=[$3]"; fi; }

run() {
	label=$1; bin=$2; mode=$3; port=$4
	(cd real && python3 evil_socks5.py "$port" "$mode") & pid=$!
	sleep 1
	set +e
	(cd real && ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 timeout 20 \
	  "$bin" /dev/null "SOCKS5:127.0.0.1:127.0.0.1:85,socksport=$port") \
	  > "real/evidence-real-$label.out" 2>&1
	rc=$?

	kill "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	return "$rc"
}

# Vulnerable attack: the negative read count reaches the kernel as SIZE_MAX.
run vuln-attack ./socat-1.8.1.1/socat attack 18441; vrc=$?
out=real/evidence-real-vuln-attack.out
ck vuln-attack-rc "$([ "$vrc" -ne 0 ] && echo nonzero)" nonzero
ck vuln-attack-efault "$(grep -c 'Bad address' "$out")" 1
ck vuln-attack-noasan "$(grep -c 'AddressSanitizer' "$out")" 0

run vuln-safe ./socat-1.8.1.1/socat safe 18442; ck vuln-safe-rc "$?" 0
ck vuln-safe-noasan "$(grep -c 'AddressSanitizer' real/evidence-real-vuln-safe.out)" 0
run fixed-attack ./socat-1.8.1.2/socat attack 18443; ck fixed-attack-rc "$?" 0
ck fixed-attack-noasan "$(grep -c 'AddressSanitizer' real/evidence-real-fixed-attack.out)" 0
run fixed-safe ./socat-1.8.1.2/socat safe 18444; ck fixed-safe-rc "$?" 0
ck fixed-safe-noasan "$(grep -c 'AddressSanitizer' real/evidence-real-fixed-safe.out)" 0

echo "TOTAL pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
