#!/bin/sh
# W171 bounded replay: synthetic one-shot 127.0.0.1 wire-input lane over the
# existing pinned real-library static builds. Reuses build/; never rebuilds.
# Each case starts one consumer, waits for its printed ephemeral port, sends
# one payload in a single connection, and waits for the consumer to exit.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
mkdir -p evidence

COMMON="-std=c++11 -g -O1 -Wall -Wextra"
g++ $COMMON -DWIRE_VICTIM \
	-I build/vuln-2_8_3-plain/include -I build/vuln-2_8_3-plain/include/mt32emu \
	wire_driver.cpp build/vuln-2_8_3-plain/libmt32emu.a -o wire-vuln-plain
g++ $COMMON \
	-I build/fixed-1749f7f-plain/include -I build/fixed-1749f7f-plain/include/mt32emu \
	wire_driver.cpp build/fixed-1749f7f-plain/libmt32emu.a -o wire-fixed-plain
g++ $COMMON -fsanitize=address -fno-omit-frame-pointer \
	-I build/vuln-2_8_3-asan/include -I build/vuln-2_8_3-asan/include/mt32emu \
	wire_driver.cpp build/vuln-2_8_3-asan/libmt32emu.a -o wire-vuln-asan
g++ $COMMON -fsanitize=address -fno-omit-frame-pointer \
	-I build/fixed-1749f7f-asan/include -I build/fixed-1749f7f-asan/include/mt32emu \
	wire_driver.cpp build/fixed-1749f7f-asan/libmt32emu.a -o wire-fixed-asan

: > evidence/wire-results.txt
run_case() {
	bin=$1
	kind=$2
	tag=$3
	portfile="evidence/.wire-${tag}.port"
	rm -f "$portfile"
	"$bin" "$portfile" >"evidence/wire-server-${tag}.out" 2>&1 &
	pid=$!
	i=0
	while [ ! -s "$portfile" ]; do
		i=$((i + 1))
		if [ "$i" -gt 200 ]; then
			echo "PORT TIMEOUT $tag" >&2
			kill "$pid" 2>/dev/null || true
			wait "$pid" 2>/dev/null || true
			return 1
		fi
		sleep 0.05
	done
	port=$(cat "$portfile")
	python3 wire_client.py 127.0.0.1 "$port" "$kind" >"evidence/wire-client-${tag}.out" 2>&1
	set +e
	wait "$pid"
	rc=$?
	set -e
	printf '%s rc=%d\n' "$tag" "$rc" | tee -a evidence/wire-results.txt
	rm -f "$portfile"
}

run_case ./wire-vuln-plain attack vuln-plain-attack
run_case ./wire-vuln-plain safe vuln-plain-safe
run_case ./wire-fixed-plain attack fixed-plain-attack
run_case ./wire-vuln-asan attack vuln-asan-attack
run_case ./wire-vuln-asan safe vuln-asan-safe
run_case ./wire-fixed-asan attack fixed-asan-attack
run_case ./wire-vuln-plain safe-fit vuln-plain-safe-fit
run_case ./wire-fixed-plain safe-fit fixed-plain-safe-fit
