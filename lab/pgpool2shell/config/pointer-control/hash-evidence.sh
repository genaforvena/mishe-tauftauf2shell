#!/bin/bash
# Normalize the decisive lines of the W12 pointer-control negative control.
# Full gdb transcripts contain PIDs, timestamps and build-local addresses;
# only the lines carrying the measured outcome are hashed. Peer-chosen values
# are preserved because they are the result, not ASLR.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 2
python3 - <<'PY'
import hashlib
import pathlib
import re
CHOSEN = ("0x558cfca8", "0x558c5ad8", "0x11111111",
          "0x00005555558cfca8", "0x00005555558c5ad8", "0x0000555511111111")
GENERIC = [
    (re.compile(r'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+'), 'TIMESTAMP'),
    (re.compile(r'pid \d+'), 'pid PID'),
    (re.compile(r'PID:\d+'), 'PID:PID'),
    (re.compile(r'process \d+'), 'process PID'),
    (re.compile(r'LWP \d+'), 'LWP PID'),
    (re.compile(r'0x[0-9a-f]{6,}'), '0xADDR'),
    (re.compile(r'0x[0-9A-F]{6,}'), '0xADDR'),
]
DECISIVE = re.compile(
    r'^===|0x55555591dbe0:|json_value_free_ex|free\(\): invalid pointer|'
    r'received signal SIG(SEGV|ABRT)|visited-count|free_ex visit|'
    r'HIT config parser|Breakpoint 2\.2|backend_port0|free_ex \(value='
)


def normalize(text):
    marks = {}
    for i, c in enumerate(CHOSEN):
        mark = f'CHOSEN{i}'
        marks[mark] = c
        text = text.replace(c, mark)
    for pattern, repl in GENERIC:
        text = pattern.sub(repl, text)
    for mark, c in marks.items():
        text = text.replace(mark, c)
    return text


lines = []
for name in ('before.out', 'restore-count.out', 'restore-count2.out',
             'root-count.out'):
    p = pathlib.Path(name)
    kept = [ln for ln in p.read_text(errors='replace').splitlines()
            if DECISIVE.search(ln)]
    digest = hashlib.sha256(normalize('\n'.join(kept)).encode()).hexdigest()
    lines.append(f'{digest}  {name}\n')

pathlib.Path('EVIDENCE_HASHES.txt').write_text(''.join(lines))
print('wrote EVIDENCE_HASHES.txt')
PY
cat EVIDENCE_HASHES.txt
