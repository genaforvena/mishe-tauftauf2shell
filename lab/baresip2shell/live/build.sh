#!/bin/bash
# Build pinned libre (v4.8.0 / v4.8.1) with and without ASan, then link the
# loopback websock_accept server. Provisioning of src/re and src/re-fixed is
# described in reports/baresip2shell-status.md.
set -u
BASE=$(cd "$(dirname "$0")/.." && pwd)
LIVE="$BASE/live"
mkdir -p "$BASE/build" "$LIVE"
SAN="-g -O0 -fno-omit-frame-pointer -fsanitize=address -fno-sanitize-recover=all"
LIBS="-lm -lresolv -lz -lssl -lcrypto -ldl -lpthread"

for mode in asan plain; do
	for v in vuln fixed; do
		src="$BASE/src/re"
		[ "$v" = fixed ] && src="$BASE/src/re-fixed"
		if [ "$mode" = asan ]; then
			dir="$BASE/build/re-$v"
			cflags="$SAN"
			ldflags="-fsanitize=address"
			server="$LIVE/ws_server-$v"
		else
			dir="$BASE/build/re-plain-$v"
			cflags="-g -O0 -fno-omit-frame-pointer"
			ldflags=""
			server="$LIVE/ws_server-plain-$v"
		fi
		if [ ! -f "$dir/libre.a" ]; then
			cmake -S "$src" -B "$dir" -DCMAKE_BUILD_TYPE=Debug \
				-DLIBRE_BUILD_SHARED=OFF -DUSE_OPENSSL=ON \
				-DCMAKE_C_FLAGS="$cflags" \
				-DCMAKE_EXE_LINKER_FLAGS="$ldflags" \
				> "$BASE/build/cfg-$mode-$v.log" 2>&1 || {
				echo "CONFIG_FAIL=$mode-$v"
				exit 1
			}
			cmake --build "$dir" -j2 > "$BASE/build/build-$mode-$v.log" 2>&1 || {
				echo "LIB_BUILD_FAIL=$mode-$v"
				exit 1
			}
		fi
		gcc $cflags -I "$src/include" "$LIVE/ws_server.c" \
			"$dir/libre.a" -o "$server" $LIBS \
			> "$LIVE/build-$mode-$v.log" 2>&1 || {
			echo "SERVER_BUILD_FAIL=$mode-$v"
			exit 1
		}
		echo "BUILD_OK=$mode-$v"
	done
done
