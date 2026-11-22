#!/bin/bash
# Normalize the decisive lines of the W9 wire evidence and record SHA256 hashes.
# Full daemon logs contain ephemeral ports, PIDs and timing-dependent line
# counts, so only the lines that carry the measured outcome are hashed.
# Replay: bash run.sh; bash gdb-run.sh ...; bash hash-evidence.sh; compare.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 2
python3 - <<'PY'
import hashlib
import pathlib
import re

# Peer-chosen values are the measured result, not ASLR.
CHOSEN = ("0x5555555555555555", "0x4141414141414141",
          "0x42424242", "0x11111111")
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
    r'type:\[CONFIG DATA\]|invalid watchdog configuration JSON|'
    r'configured with \d+ watchdog nodes|terminated by segmentation fault|'
    r'HIT after get_pool_config_from_json|^(\$|\dx|#|standard_packet_processor|===)')


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


def digest(text):
    return hashlib.sha256(normalize(text).encode()).hexdigest()


lines = []
for p in sorted(pathlib.Path('.').glob('evidence-*')):
    if p.name.endswith('.stdout'):
        kept = [ln for ln in p.read_text(errors='replace').splitlines()
                if DECISIVE.search(ln)]
    elif p.name.endswith('.peer'):
        kept = [ln for ln in p.read_text(errors='replace').splitlines()
                if ln.startswith('peer listening') or
                ln.startswith('peer sent type=Z')]
    else:
        kept = p.read_text(errors='replace').splitlines()
    lines.append(f"{digest(chr(10).join(kept))}  {p.name}\n")

for p in sorted(pathlib.Path('.').glob('gdb-w9*.out')):
    text = p.read_text(errors='replace')
    marker = '=== HIT after get_pool_config_from_json returned ==='
    kept = text.split(marker, 1)[1].splitlines()[:14] if marker in text else text.splitlines()
    lines.append(f"{digest(chr(10).join(kept))}  {p.name}\n")

pathlib.Path('EVIDENCE_HASHES.txt').write_text(''.join(lines))
print('wrote EVIDENCE_HASHES.txt')
PY
cat EVIDENCE_HASHES.txt
