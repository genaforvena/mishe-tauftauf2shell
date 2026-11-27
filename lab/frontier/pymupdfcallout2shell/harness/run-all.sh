#!/bin/sh
# Replay the pinned PyMuPDF callout arms from a clean checkout.
# Provisioning pinned public PyPI wheels is allowed; no external target is
# contacted. All runs are local Python API calls, no server or wire.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
mkdir -p evidence
VULN=venv
FIXED=venv-fixed
REPRO=harness/repro.py
SPEC='41200000,41200000,41200000,41200000,41200000,41200000,41200000,41200000,00582130:00000000,43434343:43434343'

provision() {
  d=$1; version=$2
  if [ ! -x "$d/bin/python" ]; then python3 -m venv "$d"; fi
  if ! "$d/bin/python" -c "import pymupdf,sys; sys.exit(pymupdf.VersionBind != '$version')" 2>/dev/null; then
    "$d/bin/pip" install --no-deps --disable-pip-version-check -q "pymupdf==$version"
  fi
}
provision "$VULN" 1.28.2
provision "$FIXED" 2.0

fails=0
check() {
  name=$1; shift
  if "$@"; then echo "PASS $name"; else echo "FAIL $name"; fails=$((fails+1)); fi
}

run() {
  out=$1; py=$2; shift 2
  set +e
  "$py" "$REPRO" "$@" > "evidence/$out.out" 2>&1
  echo $? > "evidence/$out.rc"
  set -e
}

run vuln-safe3 "$VULN/bin/python" 3
check vuln-safe3 sh -c "test \"\$(cat evidence/vuln-safe3.rc)\" = 0 && grep -q NO_CRASH evidence/vuln-safe3.out"

run vuln-crash8 "$VULN/bin/python" 8 43434343
check vuln-crash8 sh -c "test \"\$(cat evidence/vuln-crash8.rc)\" = 139 && grep -q 'spec=43434343' evidence/vuln-crash8.out"

set +e
gdb -q -batch -x harness/gdb-callout.cmd --args "$VULN/bin/python" "$REPRO" 10 "$SPEC" > evidence/gdb-rip10.out 2>&1
gdb_rc=$?
set -e
echo "$gdb_rc" > evidence/gdb-rip10.rc
check gdb-chosen-saved-rip sh -c "grep -q 'ENTRY_RET=0x582190' evidence/gdb-rip10.out && grep -q '0x4343434343434343' evidence/gdb-rip10.out && grep -q '0x0000000000582130' evidence/gdb-rip10.out"

run fixed-safe3 "$FIXED/bin/python" 3
check fixed-safe3 sh -c "test \"\$(cat evidence/fixed-safe3.rc)\" = 0 && grep -q NO_CRASH evidence/fixed-safe3.out"

run fixed-attack100 "$FIXED/bin/python" 100
check fixed-attack100 sh -c "test \"\$(cat evidence/fixed-attack100.rc)\" = 1 && grep -q 'RuntimeError: bad seq of points' evidence/fixed-attack100.out"

if [ "$fails" -eq 0 ]; then echo "RUN_ALL_OK 5 PASS / 0 FAIL"; else echo "RUN_ALL_FAIL $fails"; exit 1; fi
