#!/usr/bin/env python3
"""CVE-2026-129291 (GHSA-jm4m-qfqx-967m): FPM epoll use-after-free lane.

Runs the vendor's own regression test, added in 8.5.13 as
sapi/fpm/tests/ghsa-g3vh-838c-65v7.phpt, against one affected and one fixed
FPM *build directory*. The test drives a loopback Unix-socket FPM instance
with a fatal error during session shutdown after fastcgi_finish_request();
a correctly fixed master terminates and replaces the worker (bool(true)).

The verbatim phpt body is embedded below for clean-checkout replay; it is
copied into each build's sapi/fpm/tests/ before `make test`, which is how
the FPM tester harness finds its php-fpm binary.

Usage:
  python3 php2shell-cve129291-fpm.py AFFECTED_BUILD FIXED_BUILD [OUTDIR]

No network: the FPM tester binds a Unix socket in a local temp directory.
The observed pair was 8.4.27 (affected) and 8.4.28 (fixed), both FPM ASan
builds. This test is a functional fault test: it does not by itself produce
an ASan/UBSan report, so it establishes a reproducible, fix-sensitive fault
and NOT confirmed memory corruption.
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys

PHPT_NAME = 'ghsa-g3vh-838c-65v7.phpt'
PHPT = r'''--TEST--
FPM: GHSA-g3vh-838c-65v7 terminates a worker after interrupted session shutdown
--EXTENSIONS--
session
--SKIPIF--
<?php include "skipif.inc"; ?>
--FILE--
<?php
require_once "tester.inc";

$sessionDir = __DIR__ . '/ghsa-g3vh-838c-65v7.sessions';
mkdir($sessionDir, 0700);

$cfg = <<<EOT
[global]
error_log = {{FILE:LOG}}
log_level = notice
[unconfined]
listen = {{ADDR:UDS}}
pm = static
pm.max_children = 1
php_admin_value[session.save_path] = $sessionDir
php_admin_flag[opcache.enable] = off
php_admin_flag[display_errors] = off
php_admin_flag[log_errors] = off
EOT;

$code = <<<'PHP'
<?php
if ($_SERVER['QUERY_STRING'] !== 'producer') {
    echo getmypid();
    return;
}

class ShutdownStream {
    public $context;
    private $fp;

    public function stream_open($path, $mode, $options, &$openedPath) {
        $this->fp = fopen('/dev/null', 'w');
        return true;
    }

    public function stream_write($data) {
        return strlen($data);
    }

    public function stream_close() {
        trigger_error('session shutdown bailout', E_USER_ERROR);
    }
}
stream_wrapper_register('shutdown-test', ShutdownStream::class);
session_id('g3vh' . getmypid());
session_start();
$_SESSION['stream'] = fopen('shutdown-test://session', 'w');
unset($_SESSION);

// Finish the response before the fatal RSHUTDOWN callback runs.
echo 'producer';
fastcgi_finish_request();
PHP;

$tester = new FPM\Tester($cfg, $code);
$tester->start(extensions: ['session']);
$tester->expectLogStartNotices();
$pid = (int) $tester->request(address: '{{ADDR:UDS}}')->getBody();
$tester->request(query: 'producer', address: '{{ADDR:UDS}}')->expectBody('producer');
$tester->expectLogWarning(
    'child ' . $pid . ' exited with code 1 after \\d+\\.\\d+ seconds from start',
    'unconfined',
    timeoutSeconds: 5
);
$tester->expectLogNotice('child \\d+ started', 'unconfined');
$replacement = (int) $tester->request(address: '{{ADDR:UDS}}')->getBody();
var_dump($pid > 0 && $replacement > 0 && $replacement !== $pid);
$tester->terminate();
$tester->expectLogTerminatingNotices();
$tester->close();
?>
Done
--EXPECT--
bool(true)
Done
--CLEAN--
<?php
require_once "tester.inc";
FPM\Tester::clean();
$sessionDir = __DIR__ . '/ghsa-g3vh-838c-65v7.sessions';
foreach (glob($sessionDir . '/sess_*') as $file) {
    unlink($file);
}
@rmdir($sessionDir);
?>
'''


def run_build(build, outdir, tag):
    build = pathlib.Path(build).resolve()
    tests = build / 'sapi' / 'fpm' / 'tests'
    phpt = tests / PHPT_NAME
    phpt.write_text(PHPT)
    env = os.environ.copy()
    env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=0'
    env['TEST_PHP_EXECUTABLE'] = str(build / 'sapi' / 'cli' / 'php')
    cp = subprocess.run(['make', 'test', 'TESTS=sapi/fpm/tests/' + PHPT_NAME,
                         'NO_INTERACTION=1', 'REPORT_EXIT_STATUS=0'],
                        cwd=str(build), env=env, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, timeout=300)
    text = cp.stdout.decode(errors='replace')
    (outdir / f'{tag}.log').write_text(text)
    # The tester writes bool(true) only when the worker was replaced.
    lines = text.splitlines()
    verdict = 'PASS' if any(l.startswith('PASS ') for l in lines) else \
        ('FAIL' if any(l.startswith('FAIL ') for l in lines) else 'UNKNOWN')
    return verdict


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    affected, fixed = sys.argv[1], sys.argv[2]
    outdir = pathlib.Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else \
        pathlib.Path(__file__).resolve().parent.parent / 'build' / 'evidence' / 'w52-129291-fpm'
    outdir.mkdir(parents=True, exist_ok=True)
    av = run_build(affected, outdir, 'affected')
    fv = run_build(fixed, outdir, 'fixed')
    print(f'affected={av}  fixed={fv}')
    confirmed = (av == 'FAIL' and fv == 'PASS')
    verdict = 'CONFIRMED' if confirmed else 'NOT CONFIRMED'
    (outdir / 'verdict.txt').write_text(
        f'verdict: {verdict}\naffected={affected} {av}\nfixed={fixed} {fv}\n')
    print(f'verdict: {verdict}')
    return 0 if confirmed else 1


if __name__ == '__main__':
    sys.exit(main())
