#!/bin/sh
# Replay the pinned Checkmk mkevent stack-overflow arms. Local API/sink only;
# no network target, server, wire, shell or command is contacted.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
mkdir -p evidence
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

run vuln-asan-safe harness/bin/vuln-asan fill 100 0x43
check vuln-asan-safe sh -c "test \"\$(cat evidence/vuln-asan-safe.rc)\" = 0 && grep -q MESSAGE_SIZE=144 evidence/vuln-asan-safe.out"

run vuln-asan-overflow harness/bin/vuln-asan fill 10000 0x43
check vuln-asan-overflow sh -c "test \"\$(cat evidence/vuln-asan-overflow.rc)\" != 0 && grep -q 'stack-buffer-overflow' evidence/vuln-asan-overflow.out && grep -q 'WRITE of size 10000' evidence/vuln-asan-overflow.out && grep -q 'append_str' evidence/vuln-asan-overflow.out && grep -q 'mkevent.cc:144' evidence/vuln-asan-overflow.out"

run fixed-asan-safe harness/bin/fixed-asan fill 100 0x43
check fixed-asan-safe sh -c "test \"\$(cat evidence/fixed-asan-safe.rc)\" = 0 && grep -q MESSAGE_SIZE=144 evidence/fixed-asan-safe.out"

run fixed-asan-truncate harness/bin/fixed-asan fill 10000 0x43
check fixed-asan-truncate sh -c "test \"\$(cat evidence/fixed-asan-truncate.rc)\" = 0 && grep -q MESSAGE_SIZE=8191 evidence/fixed-asan-truncate.out"

run vuln-plain-safe harness/bin/vuln-plain fill 100 0x43
check vuln-plain-safe sh -c "test \"\$(cat evidence/vuln-plain-safe.rc)\" = 0 && grep -q MESSAGE_SIZE=144 evidence/vuln-plain-safe.out"

run vuln-plain-overflow harness/bin/vuln-plain fill 10000 0x43
check vuln-plain-overflow sh -c "test \"\$(cat evidence/vuln-plain-overflow.rc)\" = 139"

run fixed-plain-truncate harness/bin/fixed-plain fill 10000 0x43
check fixed-plain-truncate sh -c "test \"\$(cat evidence/fixed-plain-truncate.rc)\" = 0 && grep -q MESSAGE_SIZE=8191 evidence/fixed-plain-truncate.out"

set +e
gdb -q -batch -x harness/gdb-fill.cmd harness/bin/vuln-plain > evidence/gdb-real-parser.out 2>&1
echo $? > evidence/gdb-real-parser.rc
set -e
check gdb-real-parser-chosen-rip sh -c "grep -q '#1  0x4343434343434343' evidence/gdb-real-parser.out && grep -q 'mkevent.cc:146' evidence/gdb-real-parser.out"

run direct-rip-8172 harness/bin/vuln-direct-plain rip 8172
check direct-rip-8172 sh -c "test \"\$(cat evidence/direct-rip-8172.rc)\" = 0 && grep -q BENIGN_MARKER evidence/direct-rip-8172.out"

run direct-rip-8171 harness/bin/vuln-direct-plain rip 8171
check direct-rip-8171-negative sh -c "test \"\$(cat evidence/direct-rip-8171.rc)\" != 0 && ! grep -q BENIGN_MARKER evidence/direct-rip-8171.out"

run direct-rip-8173 harness/bin/vuln-direct-plain rip 8173
check direct-rip-8173-negative sh -c "test \"\$(cat evidence/direct-rip-8173.rc)\" != 0 && ! grep -q BENIGN_MARKER evidence/direct-rip-8173.out"

if [ "$fails" -eq 0 ]; then
  echo RUN_ALL_OK 11 PASS / 0 FAIL | tee evidence/last-run.out
else
  echo RUN_ALL_FAIL "$fails" | tee evidence/last-run.out
  exit 1
fi
