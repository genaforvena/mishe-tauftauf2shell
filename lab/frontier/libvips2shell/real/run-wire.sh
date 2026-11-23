#!/usr/bin/env bash
# W14: crafted/safe TIFF bytes over a real 127.0.0.1 socket into the pinned
# header-only libvips load path, vulnerable vs fixed. No pixel decode, paint,
# command or marker. Ephemeral port; no external address.
set -u
cd "$(dirname "$0")" || exit 1

ROOT=$(cd .. && pwd)
VULN_LIB="$ROOT/build-vuln-plain/libvips"
FIXED_LIB="$ROOT/build-fixed-plain/libvips"
for d in "$VULN_LIB" "$FIXED_LIB"; do
	if [ ! -f "$d/libvips.so.42" ]; then
		echo "MISSING BUILD: $d" >&2
		exit 2
	fi
done

INC="$(pkg-config --cflags glib-2.0 gobject-2.0) -I$ROOT/src/libvips-8.18.2/libvips/include"
LIB=$(pkg-config --libs glib-2.0 gobject-2.0)
CFLAGS="-g -O0 -DHAVE_CONFIG_H"

gcc $CFLAGS -I"$ROOT/build-vuln-plain" -I"$ROOT/build-vuln-plain/libvips/include" \
	$INC -o wire-plain wire.c -L"$VULN_LIB" -lvips $LIB || exit 1
gcc $CFLAGS -I"$ROOT/build-fixed-plain" -I"$ROOT/build-fixed-plain/libvips/include" \
	-I"$ROOT/src/libvips-fixed/libvips/include" $INC -o wire-fixed wire.c \
	-L"$FIXED_LIB" -lvips $LIB || exit 1

send_post() {
	local port=$1 tif=$2
	python3 - "$port" "$tif" <<'PY'
import socket, sys
port = int(sys.argv[1])
body = open(sys.argv[2], "rb").read()
s = socket.create_connection(("127.0.0.1", port), 5)
head = ("POST /upload HTTP/1.0\r\nHost: 127.0.0.1\r\n"
        "Content-Length: %d\r\n\r\n" % len(body)).encode()
s.sendall(head + body)
s.shutdown(socket.SHUT_WR)
s.settimeout(5)
try:
    s.recv(4096)
except Exception:
    pass
s.close()
PY
}

run() {
	local lib=$1 bin=$2 out=$3 tif=$4
	rm -f "$out"
	LD_LIBRARY_PATH="$lib" timeout 60 "./$bin" >"$out" 2>&1 &
	local pid=$!
	local port="" i
	for i in $(seq 1 100); do
		port=$(grep -oE 'port=[0-9]+' "$out" 2>/dev/null | head -1 | cut -d= -f2)
		[ -n "$port" ] && break
		sleep 0.05
	done
	if [ -z "$port" ]; then
		echo "PORT_TIMEOUT $out" >>"$out"
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
	else
		send_post "$port" "$tif" >>"$out" 2>&1
		wait "$pid"
	fi
	printf 'RUN_RC=%d\n' "$?" >>"$out"
}

run "$VULN_LIB" wire-plain wire-vuln-crafted.out manyband.tif
run "$VULN_LIB" wire-plain wire-vuln-safe.out safe.tif
run "$FIXED_LIB" wire-fixed wire-fixed-crafted.out manyband.tif
run "$FIXED_LIB" wire-fixed wire-fixed-safe.out safe.tif

fail=0
check() {
	if grep -qF "$2" "$1"; then
		echo "PASS $1 :: $2"
	else
		echo "FAIL $1 :: $2"
		fail=1
	fi
}
absent() {
	if grep -qF "$2" "$1"; then
		echo "FAIL $1 :: must not contain $2"
		fail=1
	else
		echo "PASS $1 :: absent $2"
	fi
}

# Vulnerable + crafted request bytes: header accepted, oversized line observed.
check wire-vuln-crafted.out 'WIRE_BIND 127.0.0.1 port='
check wire-vuln-crafted.out 'WIRE_REQ body=154 content_length=154'
check wire-vuln-crafted.out 'WIRE_HDR Xsize=107374 Ysize=2 Bands=10000 BandFmt=6 sizeof_line=4294960000'
check wire-vuln-crafted.out 'WIRE_SANITY=1 msg='
check wire-vuln-crafted.out 'RUN_RC=0'

# Vulnerable + safe request bytes: ordinary image still accepted.
check wire-vuln-safe.out 'WIRE_HDR Xsize=64 Ysize=2 Bands=4'
check wire-vuln-safe.out 'WIRE_SANITY=1 msg='
check wire-vuln-safe.out 'RUN_RC=0'

# Fixed + crafted request bytes: rejected by the pinned guard.
check wire-fixed-crafted.out 'WIRE_HDR=ERR msg=image: dimension overflow'
absent wire-fixed-crafted.out 'WIRE_HDR Xsize=107374'
check wire-fixed-crafted.out 'RUN_RC=0'

# Fixed + safe request bytes: fixed build is not broadly rejecting.
check wire-fixed-safe.out 'WIRE_HDR Xsize=64 Ysize=2 Bands=4'
check wire-fixed-safe.out 'RUN_RC=0'

echo "RESULT fail=$fail"
exit "$fail"
