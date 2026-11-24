#!/usr/bin/env bash
# Extract the verbatim answer() TERM-copy hunks from the pinned sources.
# No hand-typed copy of the vulnerable or fixed code is used by the harness.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
from pathlib import Path
p = Path('pins')
vuln = p.joinpath('answer-parent.cpp').read_text().splitlines()
fixed = p.joinpath('answer-fixed.cpp').read_text().splitlines()
helper = p.joinpath('ssl.c').read_text().splitlines()

def emit(name, lines, first, last):
    body = '\n'.join(lines[first - 1:last]) + '\n'
    Path('harness', name).write_text(body)
    print(f'{name}: pinned lines {first}-{last}, {len(body)} bytes')

# Vulnerable call and its terminator logic (parent of fix cb6d77dbca).
emit('vuln.inc', vuln, 543, 549)
# Fixed call, SAFECOPY and cleanup (fix cb6d77dbca).
emit('fixed.inc', fixed, 542, 549)
# The length-querying helper introduced by the fix, verbatim from pinned ssl.c.
emit('helper.inc', helper, 34, 61)
PY
