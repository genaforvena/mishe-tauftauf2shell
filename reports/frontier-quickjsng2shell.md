# frontier-quickjsng2shell — fast-array use-after-free (GHSA-r6vf-p8wr-4vg9)

Status: **STAGED, rung 3 ASan-confirmed in verbatim pinned source (W279,
2026-11-26)**. Highest-ranked of six verified candidates from two read-only
advisory sweeps: a six-line upstream regression input, a one-line always-on
fix, and a real `qjs` CLI file path. Pins, hashes, refetch URLs and preserved
negatives are in `lab/frontier/quickjsng2shell/PROVENANCE.md`.

## Claim source and scope

- GitHub Security Advisory
  `https://github.com/quickjs-ng/quickjs/security/advisories/GHSA-r6vf-p8wr-4vg9`
  (fetched 200, saved HTML SHA-256 in PROVENANCE). **No CVE**; the advisory
  says "No known CVE", and an OSV lookup for the GHSA returned HTTP 404 in the
  read-only scout. CWE-416 use-after-free.
- Advisory metadata says affected `<0.14.0` and "Patched versions: None", but
  that label is contradicted by the source: tag `v0.14.0`
  (`3c051980ab7e783dfbfb1c70c014ce5e05ecf24c`) is still vulnerable, and tag
  `v0.15.0` (`433941b99fb3c5e7f98b7ebd78727972bcf467ee`) contains the fix.
  Pins are by tag, not by advisory text. The earlier note in the
  `quickjsbcode2shell` brief that the advisory page 404s is stale.
- Fix commit `da49a37041e78ba7148b24bf6500c4c18c8ecbb0` ("Addresses an
  incomplete fix from 1b0b660", 2026-05-11): one added line in `quickjs.c` and
  a six-line regression test, fetched patch SHA-256
  `a19b577e7ba33f2ab231104a540b1c480e726bd51a5e2c7b54f1f7d94cf5b38d`.
- Advisory PoC `poc.js` and upstream ASan trace are saved under
  `lab/frontier/quickjsng2shell/src/`; the PoC is byte-identical to the test
  added by the fix commit.
- Checked before staging: no brief, charter, lane, wall entry or window named
  for quickjs-ng; not on the do-not-duplicate list. This is a distinct project
  from the staged bellard/quickjs `quickjsbcode2shell` (CVE-2026-88378).

## Source-bound mechanism (pinned bytes)

Read from the verbatim pinned `quickjs.c`:

- `set_array_length()` starts at v0.14.0 `:9862`. On a fast-array shrink its
  loop at `:9880` calls `JS_FreeValue(ctx, p->u.array.u.values[i]);` but leaves
  the freed pointer stored in `p->u.array.u.values[i]`, then sets
  `count = len` and writes the new `length` property. Growing the length back
  updates only the property, not the count or the stale slots.
- The PoC then pushes a new object and reads `arr[3]`. The stale pointer is
  treated as a live JSValue: v0.15.0 `:9930-9931` shows the fix, which clears
  each slot with `p->u.array.u.values[i] = JS_UNDEFINED;` immediately after
  the free. Extracting the whole function from each pin gives a diff of
  exactly one added line.
- The advisory's optional GC variant (freeing the array with stale pointers
  still in its `values[]`) was published as a separate ASan trace; this lab
  reproduced the direct read variant from the upstream regression test.

## Local experiment and observed bytes

`lab/frontier/quickjsng2shell/run-all.sh` checks all hashes, extracts both
tarballs, verifies the verbatim `quickjs.c` bytes and one-line function diff,
then builds the ordinary `qjs` CLI from unmodified pinned sources with GCC
13.3 `-fsanitize=address` (plus each tag's generated repl/standalone bytecode
sources). No upstream source line is edited; no socket is opened.

`sh run-all.sh && sh verify.sh` produced `RESULT PASS=28 FAIL=0` and
`RESULT PASS=11 FAIL=0`.

- Exact upstream PoC on v0.14.0: GCC ASan `heap-use-after-free`,
  `READ of size 4`, `js_dup build/vuln/quickjs.c:1546` via
  `js_get_fast_array_element build/vuln/quickjs.c:9478`, address 0 bytes inside
  a 72-byte freed region; rc 1.
- Same PoC on v0.15.0: rc 0, prints `undefined`, no ASan report — the cleared
  slot reads as an empty array element.
- Safe control (shrink to 2, read only live slots): `2` and `[1,2]` on both
  pins, rc 0, no ASan report.

## Honest grade

Rung 3: ASan-confirmed heap use-after-free READ-4 in verbatim pinned upstream
source, reached by feeding the upstream regression script to the shipped `qjs`
CLI. Rung 2 is the observable length/count divergence and the fixed clean
`undefined` readback. Rung 4 **NOT CLAIMED**: no chosen bytes observed at chosen
offsets, no pointer or control-flow steering, no fake object or function
pointer, no command, no r5. The advisory's os-module command-execution claim
was not tested or observed. There is no network listener; the input is a local
script file.

## Cheapest next experiment to move up a rung

On a plain (non-ASan) v0.14.0 build, replace each freed JS object's backing
allocation with an attacker-chosen JSON object of the same size through the
array regrow/push sequence, then read `arr[3]` and observe chosen field bytes
through `JSON.stringify`. A rung-4 claim needs that observed readback at a
chosen offset, not just a larger UAF walk. If that works, check whether the
stale JSValue's tag can be made to select a chosen object type without
crashing, and whether any shipped quickjs-ng consumer passes script text from
a loopback socket. Do not infer RCE from the advisory's claim.

## Ranked alternatives from this sweep

- sox_ng CVE-2026-129264 / GHSA-GWH5-2VHJ-GVCC: VOC ADPCM cross-block OOB
  WRITE with public PoCs and a published ASan trace; stronger write primitive
  but a larger audio-tool build and Codeberg provisioning. Next candidate.
- Gravity CVE-2026-90716: one-line number-parser guard and `x=0` input, but
  the shipped CLI over-allocates and null-terminates; reachable only through
  an embedder's exact-size buffer.
- miniaudio BEXT and libexpat ParseBuffer: deterministic file/API READs with
  focused fixes, but no numeric fixed miniaudio release and an API-misuse
  trigger for expat respectively.
- Retained backups: FRR CVE-2026-129217 (BGP daemon/session needed) and
  ntfs-3g CVE-2026-42618 (crafted NTFS image + ~100-line fix) ranked lower;
  ntfs-3g was previously screened down.

## Do-not-duplicate and boundaries

No admitted target or screened lane is reused. All execution was local against
pinned source; no external host was probed and no advisory command was run.
Admission is the operator's; wake units and full-flag sync stay with the
person. Witness replay from a clean archive is owed before any ESTABLISHED
verdict.
