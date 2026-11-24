#!/bin/bash
# W186 replay check for the fixed-build real-process control.
# Run from the repository root; checks committed pins and evidence only.
set -u
cd "$(git rev-parse --show-toplevel)" || exit 1
B=lab/frontier/kicad2shell
P="$B/provisioned/kicad10-config/10.0"
PINS="$B/realprocess/fixtures/PINS-w186.sha256"
PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

check "driver parses" "bash -n '$B/provisioned/gui-import10b.sh'"
if sha256sum -c "$PINS" >/dev/null 2>&1; then ok "14 pinned inputs match"; else bad "14 pinned inputs match"; sha256sum -c "$PINS" | grep -v OK; fi
check "safe rc alive" "[ \"\$(cat '$B/realprocess/evidence/w186-fixed-safe.rc')\" = alive ]"
check "attack rc alive" "[ \"\$(cat '$B/realprocess/evidence/w186-fixed-attack.rc')\" = alive ]"
check "gdb log has no crash marker" "! grep -qE 'Program received signal|SIGABRT|SIGSEGV|double free|corruption' '$B/realprocess/evidence/w186-fixed-attack-gdb.log'"
check "privacy prompts suppressed" "[ \"\$(python3 -c \"import json;d=json.load(open('$P/kicad_common.json'));n=d['do_not_show_again'];print(n['update_check_prompt'] and n['data_collection_prompt'])\")\" = True ]"
check "stock table rows removed" "! grep -q 'KiCad' '$P/fp-lib-table' '$P/design-block-lib-table'"
check "local symbol table present" "grep -q '(lib (name \"local\")' '$P/sym-lib-table'"
check "report section 16 present" "grep -q '^## 16\\. Fixed-build real-process control' reports/frontier-kicad2shell.md"
check "provenance exists" "[ -s '$B/realprocess/PROVENANCE-fixed-control.md' ]"

trace=$(while read -r h f; do cat "$f"; done < "$PINS" | sha256sum | cut -d' ' -f1)
echo "PASS=$PASS FAIL=$FAIL"
echo "TRACE=$trace"
[ "$FAIL" -eq 0 ]
