#!/usr/bin/env python3
"""CVE-2026-129538: HTTP reachability through a real loopback web server.

Apache 2.4.71 (mod_proxy_fcgi DSO) listens on 127.0.0.1:18080 and forwards every
request over FastCGI to a pinned php-cgi responder on 127.0.0.1:18951. The PHP
target prints the corrected $_SERVER values so an HTTP request path alone
decides whether the 129538 underflow shape is reachable.

Usage: python3 lab/repro/php2shell-cve129538-http.py [OUTDIR]
"""
import shutil
import os
import pathlib
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / 'build'
APACHE = (ROOT.parent / 'lab/frontier/apache2root/httpd-2.4.71/httpd')
BUILDS = (
    ('8.5.12-asan', BUILD / 'php-8.5.12-asan/sapi/cgi/php-cgi'),
    ('8.5.13-asan', BUILD / 'php-8.5.13-asan/sapi/cgi/php-cgi'),
)
FCGI_PORT = 18951
HTTP_PORT = 18080
TARGET_PHP = ('<?php foreach (["PATH_INFO","ORIG_PATH_INFO","SCRIPT_FILENAME",'
              '"SCRIPT_NAME"] as $k) echo $k,"=",$_SERVER[$k]??"NULL","|";')


def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def http_get(path, log):
    url = 'http://127.0.0.1:%d%s' % (HTTP_PORT, path)
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            body = r.read().decode(errors='replace').strip()
            status = r.status
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors='replace').strip()
        status = e.code
    except Exception as e:
        body = 'ERROR %s' % e
        status = -1
    log.write('  GET %-42s -> %d %s\n' % (path, status, body))
    return body


def main():
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else
                       'lab/build/evidence/w49-http')
    out.mkdir(parents=True, exist_ok=True)
    conf = (ROOT / 'repro/php2shell-cve129538-httpd.conf').read_text()
    (out / 'httpd.conf').write_text(conf.replace('@OUTDIR@', str(out)))
    docroot = out / 'docroot'
    docroot.mkdir(exist_ok=True)
    (docroot / 'target.php').write_text(TARGET_PHP)
    verdict = {}
    try:
        with (out / 'verdict.txt').open('w') as log:
            for tag, binary in BUILDS:
                log.write('=== %s: %s ===\n' % (tag, binary))
                env = dict(os.environ)
                env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=1'
                with (out / ('%s-fcgi.log' % tag)).open('wb') as flog:
                    gp = subprocess.Popen(
                        [str(binary), '-n', '-b', '127.0.0.1:%d' % FCGI_PORT,
                         '-d', 'cgi.fix_pathinfo=1'],
                        env=env, stdout=flog, stderr=subprocess.STDOUT,
                        start_new_session=True)
                    ap = None
                    try:
                        if not wait_port(FCGI_PORT):
                            log.write('  no FastCGI listener\n')
                            continue
                        with (out / ('%s-httpd.log' % tag)).open('wb') as hlog:
                            conf_rel = os.path.relpath(
                                out / 'httpd.conf',
                                APACHE.parent.parent / 'install-2.4.71-asan')
                            ap = subprocess.Popen(
                                [str(APACHE), '-f', conf_rel, '-DFOREGROUND'],
                                stdout=hlog, stderr=subprocess.STDOUT,
                                start_new_session=True)
                            if not wait_port(HTTP_PORT):
                                log.write('  no HTTP listener\n')
                                continue
                            log.write('  short path-info:\n')
                            http_get('/target.php/b', log)
                            log.write('  long path-info (n=16):\n')
                            verdict[tag] = http_get('/target.php/' + 'x' * 16, log)
                            log.write('  long path-info (n=20):\n')
                            http_get('/target.php/' + 'x' * 20, log)
                    finally:
                        if ap is not None:
                            os.killpg(ap.pid, signal.SIGTERM)
                        os.killpg(gp.pid, signal.SIGTERM)
                        for p in (ap, gp):
                            if p is None:
                                continue
                            try:
                                p.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                os.killpg(p.pid, signal.SIGKILL)
                                p.wait()
            # Trigger shape = long suffix in SCRIPT_FILENAME while PATH_INFO
            # stays short; observed mapping is the opposite on both builds.
            v12 = verdict.get('8.5.12-asan', '')
            v13 = verdict.get('8.5.13-asan', '')
            shape = ('SCRIPT_FILENAME=' + str(out / 'docroot') +
                     '/target.php/xxxxxxxxxxxxxxxx|' in v12)
            checks = {
                'no underflow trigger shape on 8.5.12 HTTP': not shape,
                'no patch-sensitive HTTP difference (12 == 13)': v12 == v13,
            }
            for name, ok in checks.items():
                log.write('%-42s %s\n' % (name, 'PASS' if ok else 'FAIL'))
            log.write('VERDICT: %s\n' %
                      ('REACHABLE' if shape and v12 != v13 else
                       'NOT REACHABLE / INCONCLUSIVE'))
        print((out / 'verdict.txt').read_text())
    finally:
        pass


if __name__ == '__main__':
    main()
