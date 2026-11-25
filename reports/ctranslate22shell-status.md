# ctranslate22shell — admitted status (2026-11-25 11:2xZ)

Witness gate closed 2026-11-25 21:35Z: W223 replayed the one-command
wrapper and returned ESTABLISHED AS LABELED at the recorded scope. The
"witness UNKNOWN", "replay owed" and "no verdict yet" lines in the sections
below were true when written; see the dated W6 section at the end. Grade
cells, the AV:L/UI:P ceiling and the W2/W3/W4 negatives are unchanged.

**ADMITTED under standing #6 as the 148th route** by operator at 11:2xZ:
hy4-flash `max_parallel: 3` route, both resolver keys, three wake units
minted with the exact full-flag sync (`written 3, removed 0`), path enabled
and active, pinned full-flag doctor PASS / GREEN rc 0. Window 155 was
already live and registered (panes %312/%313); it was adopted, not
duplicated. No grade, rung cell or R5 cell moved by admission; witness
verdict stays UNKNOWN.

## Stage 0 — frontier staging (frontier W229, commit 7ae21617)

- CVE-2026-102566 / GHSA-7xqx-34h9-2w97, CTranslate2 before 4.8.1,
  CWE-787, CVSS4 8.5 `AV:L/UI:P`. Fix `d9b991e` (PR #2068), vulnerable
  pin `v4.8.0` `src/models/model.cc` (sha256 `05ab59bb…`), fixed pin
  sha256 `5dcc3f1d…`; both in `lab/frontier/ctranslate22shell/pins/`.
- Mechanism at pinned `:644-657`: file-derived `num_bytes` is passed to
  `consume<char>(model_file, num_bytes, variable.buffer())` at `:657`;
  `consume` at `:71` reads that many bytes into a shape-sized heap buffer.
  Fix adds the size equality check at fixed `:659-660`.
- Verbatim pinned functions + stand-in 16-byte `StorageView`:
  `bash harness/run-all.sh` = 16 PASS / 0 FAIL, GCC and Clang ASan
  `WRITE of size 17` / `WRITE of size 64`, fixed pin rejects both, safe
  payload 16 clean, plain readback shows file-chosen bytes past the region.
- Clean `git archive HEAD` replay at 11:06Z: 16 PASS / 0 FAIL.
- Grade: rung 3 confirmed in a real consumer (GCC ASan `WRITE of size 17`
  and `48` at `model.cc:657`, 0 bytes after a real 16-byte `posix_memalign`
  `StorageView` allocation); rung 4 PARTIAL file-chosen length and bytes.
  Fixed pin rejects the same file; safe 16-byte input is clean. No pointer
  control, wire, command or R5. Witness UNKNOWN; replay owed before any
  rung-4 publication.
- Brief: `reports/frontier-ctranslate22shell.md`; details and negatives in
  `lab/frontier/ctranslate22shell/PROVENANCE.md`.

## Real-source consumer — completed W1 (2026-11-25 12:05-12:08Z)

`lab/frontier/ctranslate22shell/realbuild/build.sh` builds the verbatim
upstream v4.8.0 `model.cc` (sha256 `05ab59bb…`) and fixed `d9b991e` model.cc
(sha256 `5dcc3f1d…`) against the real `StorageView`/allocator under ASan,
with only logging and unused quantization/tensor-parallel branches stubbed.
Crafted 109-byte binary_version-6 file (`realbuild/evidence/crafted-n17.bin`)
sets a shape-{2,2} FLOAT32 variable to `num_bytes=17`. ASan reports `WRITE of
size 17`, `0 bytes after 16-byte region`, allocated by `posix_memalign` via
`cpu::AlignedAllocator::allocate` ← `StorageView::reserve`; write stack
`consume<char>` ← `Model::load model.cc:657`. `num_bytes=48` writes 48 bytes;
`num_bytes=16` is clean; the fixed pin rejects the same file with
`Variable 'origin' has an invalid payload size`; the plain build aborts with
`malloc(): corrupted top size` at 48/64/80 bytes. Exact bytes and raw output
in `lab/frontier/ctranslate22shell/PROVENANCE.md` and `realbuild/evidence/`.

W2 (12:5xZ): witness replay requested by DM at 12:52Z (verdict still
UNKNOWN). `realbuild/pointer-probe.sh` measured the real heap at the store:
the 16-byte `posix_memalign` buffer is followed immediately by the top chunk,
not by a constructed pointer-bearing object; the `shared_ptr` control block
and `StorageView` are built after the store and their constructors replace
chosen bytes at +0x40/+0x48. An 80-byte chosen payload preserved allocator
metadata long enough to complete `Model::load` through the second variable,
then aborted in `sysmalloc`; no chosen pointer reached a dereference. Rung 4
stays PARTIAL. Raw gdb output in `realbuild/evidence/pointer-*.txt`; details
in `PROVENANCE.md`. Next: witness verdict, then either a groomed layout with a
pre-existing pointer object after the buffer or a measured allocator-metadata
technique. No wire path or command side effect in evidence; rung 5 NOT CLAIMED.

W3 (13:3xZ): `realbuild/harness/driver-groom.cpp` tested whether earlier
file-controlled variables can put a live pointer-bearing object after the
16-byte `origin` buffer at the `model.cc:657` store. Four gdb layouts
(filler counts 1/2/2/4, name lengths 6/16, dimension ranks 2/4/8; raw output
`realbuild/evidence/groom-*.txt`) all show zeros and top-chunk size fields
after the buffer at store time, no pointer-shaped word; buffers still come
from the top chunk and all runs completed cleanly. Grooming negative — rung 4
remains PARTIAL. Witness role wake FAILED at 13:34Z ("no working engine
candidate"); its 12:52Z replay request has no verdict and rung 4 is not
published.

## W4 (2026-11-25 15:0xZ): downstream corrupted field; witness still down

`realbuild/downstream-probe.sh` (verbatim vulnerable pin, sha256 rechecked,
deterministic 8/8) drives a file-chosen 40-byte payload into a live
`StorageView` copy after `Model::load` returns. Gdb `catch throw` at
`storage_view.cc:411` shows destination `_size=0x8282828282828282` — the
file's `0x41` payload byte — passed into `copy_from<float>` from
`get_variables()`. The `size != _size` guard blocks the actual copy, so this
is a file-derived value in a constructed object, not pointer control or
control flow: rung 4 stays PARTIAL, rung 5 NOT CLAIMED. Safe 16-byte input is
clean; fixed pin rejection unchanged from W1. A separate length sweep found
n=32 `free(): invalid next size (fast)` and n>=48 `malloc(): corrupted top
size`; a `sysmalloc`-prev_size redirect hypothesis was disproved from glibc
2.39 source and a heap dump and is discarded. Details and negatives in
`lab/frontier/ctranslate22shell/PROVENANCE.md`, raw output in
`realbuild/evidence/downstream-*`.

Witness role wake FAILED again at 14:00Z ("no working engine candidate"):
the 12:52Z replay request still has no verdict and rung 4 remains unpublished.

## W5 (2026-11-25 21:2xZ): one-command replay for witness

The witness role is waking again (its W222 closed gpgme W11 at ~21:01Z), but
this lane's 12:52Z replay ask (#4349) and the 13:3xZ operator DM (#4376) are
absent from its pending queue and detail artifacts: the engine failures lost
the request. A single offline entry point now exists:
`bash lab/frontier/ctranslate22shell/run-witness.sh`. It runs the staged
16-assertion harness, rebuilds both verbatim real-source pins with ASan,
checks both model.cc sha256s and asserts the vulnerable WRITE of size 17/48
at `model.cc:657`, the clean safe-16 control, fixed-pin rejection with
`invalid payload size`, and the plain chosen-byte/heap-corruption outputs.
DM #4575 re-offered exactly that command to `@witness` at 21:19Z, scoped to
the measured rung-3 CONFIRMED / rung-4 PARTIAL evidence only. No verdict yet:
witness stays UNKNOWN, rung 4 unpublished, rung 5 NOT CLAIMED, no grade cell
moved.

The wrapper was exercised twice from a clean shell: the first run found a BRE
escaping bug in the plain-48 assertion (`malloc\(\):` does not match in BRE);
the assertion was changed to the literal pattern and the second run printed
`WITNESS REPLAY PASS` — staged 16 PASS / 0 FAIL, both pin sha256s, all ten
real-consumer control assertions green. It is the replay path offered to the
witness in DM #4575 (21:19Z). No verdict yet: witness stays UNKNOWN, rung 4
unpublished, rung 5 NOT CLAIMED, no grade cell moved.

## W6 (2026-11-25 21:31-21:35Z): witness verdict ESTABLISHED AS LABELED

Witness W223 replayed `bash lab/frontier/ctranslate22shell/run-witness.sh`
(HEAD `305d4a68`, clean `git archive` tree, upstream v4.8.0 source from the
hash-pinned tarball): rc 0, `WITNESS REPLAY PASS`, staged harness 16 PASS /
0 FAIL, both pin sha256 values exact, all ten real-consumer assertions
green. Vulnerable ASan `WRITE of size 17` and `48` at `model.cc:657` into
the real 16-byte `posix_memalign` StorageView; fixed pin rejects n=17 with
`invalid payload size`; n=16 clean in both builds; plain n=16 chosen bytes
and plain n=48 `malloc(): corrupted top size`; three extra n=17 runs
matched. Six regenerated evidence files matched the committed outputs after
normalizing PID/addresses/build path/BuildId. Wrapper blob sha256
`b05fc1d7…` matched the HEAD blob. No counterexample found.

The replay establishes exactly the submitted evidence: rung 3 CONFIRMED in
a real consumer, rung 4 PARTIAL (file-chosen bytes and length, real heap
corruption, no pointer target or control flow), AV:L/UI:P ceiling. No wire,
live service, chosen pointer/IP or command side effect; rung 5 NOT CLAIMED;
no grade cell moved. The W2/W3/W4 negatives remain in force. Full evidence:
`.mishe-tauftauf/artifacts/witness-w223-ctranslate22shell/detail.md`; the
dated fold in `lab/frontier/ctranslate22shell/PROVENANCE.md`.

W6 follow-up (22:1xZ), same grade: a gdb inspection of the deterministic
40-byte downstream run shows the file-chosen live field is the source
`StorageView::_shape[0]` at buffer+0x20 (a `dim_t` allocated before the
store), not a pointer. Its value `0x4141…` times the untouched `shape[1]=2`
becomes the destination `_size=0x8282…`, which fails the copy guard; the
`_data` pointers live in objects constructed after the store and are
rewritten by their constructors. A variant byte payload through a hex argv
aborted before the copy (layout shift). W4's open rung-4 question is
negative for this layout; raw capture in
`realbuild/evidence/downstream-shape-40.txt`, detail in `PROVENANCE.md`.

