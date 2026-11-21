#!/usr/bin/env python3
"""CVE-2026-129501 fix hunk #2: stream-wrapper document mutation during saveXmlFile.

Exercises the SECOND 8.5.12 -> 8.5.13 ext/dom/xml_serializer.c hunk, which
wake 51's double-free harness did not touch. The old code did:

    child = node->children;
    node->children = NULL;
    TRY(xmlOutputBufferFlush(ctx->out));
    TRY(xmlSaveDoc(ctx->ctxt, (xmlDocPtr) node));
    TRY(xmlSaveFlush(ctx->ctxt));
    node->children = child;

A PHP stream wrapper's stream_write() runs during the flush/save and can reach
the real document. A failing write makes TRY bail out before the restore, so the
document keeps children == NULL; a successful write that appends a node is
undone by the stale `child` restore. The fix saves a shallow declaration_doc
with children/last NULL instead of mutating the real document.

Both --FILE-- bodies are verbatim from the 8.5.13 vendor regression tests
ext/dom/tests/modern/xml/serialize_document_write_{mutation,failure}.phpt;
both files are absent from the 8.5.12 tree.

Usage: python3 php2shell-cve129501-dom-hunk2.py VULN_BIN FIXED_BIN [OUTDIR]
No network: local CLI processes only. Default ZendMM is used (this hunk is a
DOM-tree logic fault, not an allocator fault); ASAN_OPTIONS only disables LSan.
"""
import os
import pathlib
import subprocess
import sys

MUTATION = r'''<?php

class MutatingStream {
    public $context;
    public static $doc;

    public function stream_open(string $path, string $mode, int $options, ?string &$opened_path): bool {
        return true;
    }

    public function stream_write(string $data): int {
        if (self::$doc !== null) {
            $doc = self::$doc;
            self::$doc = null;
            $doc->append($doc->createComment('injected'));
        }
        return strlen($data);
    }
}

stream_wrapper_register('mutating', MutatingStream::class);

$doc = Dom\XMLDocument::createFromString('<root><child/></root>');
MutatingStream::$doc = $doc;
$doc->saveXmlFile('mutating://out');

$doc->append($doc->createComment('after'));
var_dump($doc->childNodes->length);
echo $doc->saveXml(), "\n";
'''

MUTATION_EXPECT = '''int(3)
<?xml version="1.0" encoding="UTF-8"?>
<root><child/></root><!--injected--><!--after-->'''

FAILURE = r'''<?php

class FailingStream {
    public $context;

    public function stream_open(string $path, string $mode, int $options, ?string &$opened_path): bool {
        return true;
    }

    public function stream_write(string $data): int|false {
        return false;
    }

    public function stream_tell(): int {
        return 0;
    }
}

stream_wrapper_register('failing', FailingStream::class);

$doc = Dom\XMLDocument::createFromString('<root><child/></root>');
var_dump($doc->saveXmlFile('failing://out'));

var_dump($doc->documentElement?->nodeName);
var_dump($doc->childNodes->length);
echo $doc->saveXml();
'''

FAILURE_EXPECT = '''bool(false)
string(4) "root"
int(1)
<?xml version="1.0" encoding="UTF-8"?>
<root><child/></root>'''

CASES = [('mutation', MUTATION, MUTATION_EXPECT),
         ('failure', FAILURE, FAILURE_EXPECT)]


def run(bin_path, script, out):
    env = os.environ.copy()
    env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=0'
    cp = subprocess.run([str(bin_path), '-n', str(script)],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        timeout=120, env=env)
    text = cp.stdout.decode(errors='replace')
    out.write_text(text)
    return cp.returncode, text


def matches(text, expect):
    return text.strip() == expect.strip()


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    vuln = pathlib.Path(sys.argv[1]).resolve()
    fixed = pathlib.Path(sys.argv[2]).resolve()
    outdir = pathlib.Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else \
        pathlib.Path(__file__).resolve().parent.parent / 'build' / 'evidence' / 'w52-129501-hunk2'
    outdir.mkdir(parents=True, exist_ok=True)

    results = {}
    for name, body, expect in CASES:
        script = outdir / (name + '.php')
        script.write_text(body)
        (outdir / (name + '.expect')).write_text(expect + '\n')
        vrc, vtext = run(vuln, script, outdir / (name + '.vulnerable.log'))
        frc, ftext = run(fixed, script, outdir / (name + '.fixed.log'))
        vm, fm = matches(vtext, expect), matches(ftext, expect)
        results[name] = (vm, fm, vrc, frc)
        print(f'{name:9s} vuln rc={vrc:3d} expect={vm} | fixed rc={frc:3d} expect={fm}')
        if not vm:
            print('  vulnerable output:\n' + '\n'.join('    ' + l for l in vtext.strip().splitlines()))

    confirmed = all(not vm and fm for vm, fm, _, _ in results.values())
    verdict = 'CONFIRMED' if confirmed else 'NOT CONFIRMED'
    print(f'verdict: {verdict}')
    lines = [f'verdict: {verdict}', f'vulnerable={vuln}', f'fixed={fixed}']
    for name, (vm, fm, vrc, frc) in results.items():
        lines.append(f'{name}: vuln rc={vrc} matches_expect={vm}; fixed rc={frc} matches_expect={fm}')
    (outdir / 'verdict.txt').write_text('\n'.join(lines) + '\n')
    return 0 if confirmed else 1


if __name__ == '__main__':
    sys.exit(main())
