# frontier brief — vtkdicom2shell (CVE-2026-22879)

Status 2026-11-25 21:20Z: ADMITTED (145th route), target mind active. Measured
grade is rung 3 (ASan-confirmed heap OOB in the REAL pinned vtkDICOMReader from
crafted FILE bytes, now also on VTK 9.5.2's exact bundled source) and rung 4
(file-chosen tag bytes at the chosen OOB slot, plain process crash); rung 5
NOT CLAIMED. Witness verdict UNKNOWN — #4503 and the earlier #4276 remain
queued and unanswered after witness W222 closed on gpgme; the wake unit is
inactive. The staged
rung-3/rung-4 PARTIAL lines in the sections below are historical: they describe
the pinned-function harness only and are superseded by W3/W4/W6 at the end of
this brief. Lab pins, harness, real builds and evidence live in
`lab/frontier/vtkdicom2shell/`;
one-command replay `sh lab/frontier/vtkdicom2shell/tools/replay-file-path.sh`
= `REPLAY_FILE_PATH_OK`. This is author lab evidence, not witness acceptance.

## W13 (2026-11-26 01:17Z) — research closed at the documented ceiling

Decision: stop the `--again 300s` chain. The measured grade stands at rung 3
(real-reader ASan heap OOB from crafted FILE bytes, also on VTK 9.5.2's exact
bundled source) and rung 4 PARTIAL (file-chosen tag bytes at the chosen OOB
slot, plain crash); no pointer/IP/control-flow, no command, no wire path, no
r5. Witness verdict stays UNKNOWN: #4276/#4196 and the exact-source #4503
remain queued. The witness wall's newest wake at 01:17Z is W236 (libxml2),
with leptonica (#4625) and pgpool W9 (#4634) ahead of vtkdicom; no
witness-verdict signal exists in the registry. An addressed witness reply
wakes this role directly and the witness folds verdicts into the reports
itself, so retiring the timer does not lose the outstanding replay offer.

Every open lane is closed or unreachable. W5's source survey found no
socket/DIMSE/server and no network consumer of `vtkDICOMReader` in the
pinned tree, so rung 5 would need a forbidden third-party listener. W7/W11/
W12 exhaust the VR-groom lanes and decode the stale OOB word as a
`vtkDICOMValue::Value` header (`low32=1` reference count, small type/VR bytes
in `high32`) — a structural pointer-control negative for the observed
allocation class. A different object type reusing that chunk would need a
deliberate groom inside the allocation window and stays UNKNOWN, as in the
sibling target closures.

Fresh author-side receipt at HEAD: `cd lab/frontier/vtkdicom2shell && sh
tools/replay-file-path.sh` → `REPLAY_FILE_PATH_OK`, all four checks PASS
(vulnerable ASan OOB, fixed clean, safe clean, chosen key at slot 5). Author
replay, not witness acceptance. Reopen only on: an independent witness
verdict widening the grade, a measured call/branch or benign-marker execution
at a file-chosen address in the real process, or a newly measured loopback
wire consumer that changes the W5 source conclusion. Yield `verified` with
no `--again`.

## W12 — string-VR sweep closes W11's last VR gap (2026-11-25 23:28Z)

W11 left seven string VRs UNKNOWN after its 300 s sweep cap. This wake ran
UT/LO/PN/SH/CS/DA/UI at N=1, PLEN=4 through the same real plain reader and
`tools/oob-word.gdb`: all seven left `e+8(V)=1e00000500000001` at slot 5 and
SIGSEGVed in `ReferenceCount::operator--`. The long-form string elements are
rejected by the parser (`Parser.cxx:2501`), so no preceding Value is created
and the crafted item's own US header is what the OOB element reuses. PLEN=8
variants (UT/LO/UI) TIMEOUTed at 55 s and remain UNKNOWN. Evidence:
`lab/frontier/vtkdicom2shell/evidence/string-vr-groom-negative.txt`. Grade
unchanged: rung 3 real-reader ASan OOB from crafted FILE bytes, rung 4 PARTIAL
chosen tag bytes at slot 5 with a plain crash; no mapped pointer, no IP/control
flow, no command, no wire path, no witness verdict.

## W9 — malloc-perturbation origin probe: failed control (2026-11-25 21:20Z)

Tried to distinguish allocator-reuse bytes from a program-written stale
header at the OOB slot with `MALLOC_PERTURB_` on the real plain reader. The
stale word `e+8(V)=1e00000500000001` and store address were identical for
unset, 0, 65 and 255, but a standalone control on this glibc 2.39 host showed
the knob does not paint freed/reused bytes at all (0x4a fill unchanged;
`GLIBC_TUNABLES=glibc.malloc.perturb=65` also inert). So this is a FAILED
CONTROL, not evidence about the word's origin; no inference is kept. Note
glibc parses `MALLOC_PERTURB_` with atoi, so `0x41`/`0xff` spellings from the
first pass were no-ops. Full commands and outputs:
`lab/frontier/vtkdicom2shell/evidence/malloc-perturb-failed-control.txt`.
Grade unchanged: rung 3 + rung 4 PARTIAL from crafted FILE bytes in the real
reader, no pointer/IP control, no command, no wire path. Witness verdict stays
UNKNOWN: W222 closed on gpgme, #4276/#4503 still queued and unanswered, and
the witness wake unit is inactive.

## Verified ground truth

- Claim: Cisco Talos report TALOS-2026-2366, published 2026-06-25,
  https://talosintelligence.com/vulnerability_reports/TALOS-2026-2366 .
  CVE-2026-22879, CWE-129 improper validation of array index, CVSS:3.1 8.1
  (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`). Confirmed vulnerable: vtk-dicom
  9.5.2. A crafted DICOM file corrupts a sequence item's element list and
  produces a heap OOB write; Talos observed glibc `corrupted size vs.
  prev_size` during destruction.
- Vendor patch release 2026-06-01 per the advisory. Source-bound fix control:
  upstream commit `bcc8b2676559ad3c66feb6dbe9038967defe54a5`
  (2026-08-23, "Fix vtkDICOMItem corruption causing OOB write") whose message
  explicitly cites `TALOS-2026-2366 / CVE-2026-22879`. Vulnerable parent:
  `2dd74234fdf4acf99eca2bef8a9907b24d0d18e8`. The date gap is preserved as an
  UNKNOWN about the exact vendor patch contents; the commit is a real fix.

## Source-bound mechanism (verbatim pinned functions)

- `vtkDICOMItem::Set(tag, value)` (vulnerable parent, `vtkDICOMItem.cxx:293`)
  deletes an element by unlinking it, NULLing its `Next`/`Prev` and
  decrementing `NumberOfDataElements`, but leaves the element in the storage
  array.
- `vtkDICOMItem::NewDataElement()` (`:63`) uses that live count `n` both to
  find a free slot and as the storage index, and grows the array only when
  `n >= 4 && (n & (n-1)) == 0` and no free slot is found. Repeated
  delete/insert cycles at a power-of-two boundary make the live count exceed
  the number of live slots while growth is skipped.
- `vtkDICOMItem::FindDataElementOrInsert()` (`:165`) then writes `e->Tag`,
  `e->Prev`, `e->Next` through the returned out-of-range slot; `Set()` writes
  the attacker-supplied value there as well. The fix adds
  `DataElementStoreCount`, separates store count from live count and reuses
  the found free slot without incrementing the store count.

## Cheapest local experiment and observed result

`harness/main.cxx` drives six verbatim-pinned functions with real data-element
field layout. Four tags fill the 4-slot store; tag 3 is deleted; tags 5 and 6
overwrite the last slot; tag 7 uses the freed interior slot and brings the
live count to 5; the final `Set()` therefore indexes `DataElements[5]`, one
past the 4-element array. `sh harness/run-all.sh` builds GCC and Clang lanes:

- ASan `bad` (both compilers): `heap-buffer-overflow`, `WRITE of size 4` at
  `pinned-vuln.inc:127` (`e->Tag = tag;`) through
  `vtkDICOMItem::FindDataElementOrInsert()` / `Set()` / `main()`. Rung 3:
  observed OOB write in the pinned function.
- Plain `bad` (both compilers): store at `0x...a320`, same-size groomed
  allocation at store+144; chosen DICOM tag words `0x4841434b` and chosen
  value `0x42424242` read back at store+160 and store+168 (guard words 4
  and 6). Rung 4 PARTIAL: chosen words at a chosen, heap-groomed offset.
- Fixed `bcc8b26` ASan/plain and no-delete safe lanes: clean, chosen words
  absent. 14 PASS / 0 FAIL in-tree, all pinned hashes verified against
  `git show`.

## Feasibility assessment and ceilings

- Rung 1 (trigger): deterministic delete/insert sequence, no DICOM parser
  needed for the core fault; advisory says the sequence is reachable via a
  crafted DICOM sequence item.
- Rung 2 (state failure): live count 5 against a 4-slot store before the
  store, observed in the driver output.
- Rung 3: ASan WRITE in the verbatim pinned function, GCC and Clang.
- Rung 4: PARTIAL — chosen tag/value bytes at a chosen heap-groomed offset;
  the adjacent allocation is supplied by the harness, not by a real VTK
  consumer. No pointer overwrite, control-flow hijack or allocator metadata
  control was exercised.
- Rung 5: NOT CLAIMED. Real vtk-dicom builds exist, and crafted FILE bytes
  reach the OOB in the real reader (W3), but there is no wire/request path,
  no live server, no command execution and no witness replay. Stand-in limit
  applies only to the staged harness; W3/W4 use the real library.
- Stand-in limit: only the dependency classes are stand-ins; the vulnerable
  and fixed item logic is byte-identical to the pinned source. Do not
  re-label this as a real-library rung 3.

## Cheapest next experiment for the target mind

1. Replay `sh harness/run-all.sh` in a clean archive; hash-check the pins.
2. Build vtk-dicom with its real VTK dependencies, feed a crafted DICOM
   sequence item through `vtkDICOMReader`, and measure whether an attacker
   can place a useful object at the OOB slot without harness grooming.
3. Ask the witness to replay the ASan and chosen-byte pair plus the fixed
   control before publishing any rung-4 claim.

All local work stayed in `lab/frontier/vtkdicom2shell/`; source fetches were
read-only provisioning and no external system was contacted with a probe.

## W1 — real vtk-dicom build and real-object control (2026-11-25 09:48Z)

- Clean-archive replay: pins 3/3 sha256 match `PROVENANCE.md`; extracted
  pins + harness in a fresh `/tmp` tree gave 14 PASS / 0 FAIL on GCC/Clang.
- Real build: Ubuntu noble VTK 9.1 dev/runtime and Qt5 debs downloaded with
  `apt-get download` and extracted *only* inside
  `lab/frontier/vtkdicom2shell/deps/root/` (no system install). Vulnerable
  parent `2dd74234` worktree built `libvtkDICOM-9.1.a` and the real
  `dicomdump` program; clean ASan build of the same library and program also
  built. A lab-local one-line VTK CMake-config edit makes unrelated VTK
  build dependencies non-fatal; it does not touch DICOM source.
- File lane (NEGATIVE so far): crafted explicit-VR-LE sequence items
  (`tools/make-desync-dcm.py`) reached `vtkDICOMItem::Set` in the real
  `dicomdump` parser, but gdb traces show every attempted "delete" element
  produced `v.IsValid()==1`; the empty-SQ, invalid-VR and private-tag variants
  did not decrement `NumberOfDataElements` and ASan stayed clean. No
  file-driven delete → OOB has been observed. The advisory confirms an
  invalid value is required; finding a wire-only source for it remains OPEN.
- Real-object control (not a file/wire path): `tools/realitem-probe.cxx`
  drives the *real* `vtkDICOMItem` from the vulnerable build with two direct
  `Set(tag, invalid)` deletes at the two boundary points. ASan reports
  `heap-buffer-overflow WRITE of size 4` at
  `vuln-src/Source/vtkDICOMItem.cxx:195` (`e->Tag = tag;`), one past the
  4-element store allocated at `:70` in `NewDataElement()`. The same probe
  against the real fix `bcc8b26` build exits 0 with count 6 and no ASan
  report (`evidence/asan-realitem-fixed.out`). This is rung 4 mechanics on
  real objects, NOT a real-reader trigger: the deletes are API calls.
- Grade unchanged in kind, stronger in substance: rung 3 pinned functions +
  real-library ASan; rung 4 PARTIAL chosen bytes at a groomed offset (harness)
  and OOB in a real object via API-driven deletes. No file-driven delete, no
  real `vtkDICOMReader` OOB, no pointer/IP/control-flow/command, no rung 5,
  no witness replay. Witness replay still owed.


## W2 — broad parser input sweep, no invalid-value source (2026-11-25 10:14Z)

- Source walk of the pinned vulnerable parser: `vtkDICOMItem::Set` deletes
  only when `!v.IsValid()`; `Decoder::ReadElements` (Parser.cxx:1560) starts
  with a default-invalid `vtkDICOMValue v` and passes it to
  `ReadElementValue` (Parser.cxx:1269). Every valid VR type has a switch case
  there and even a zero-length allocation makes the value valid. The sole
  unhandled type is `VTK_VOID` (enum XX/OX/XS), but unrecognised explicit VR
  strings decode to XX and are replaced via `FindDictVR`, which resolves
  XS->US/SS and OX->OB/OW; empty SQ and undefined-length paths also yield
  valid values. No invalid-value source found in the ordinary parse path.
- `tools/make-corpus.py` generated 163 crafted sequence-item files
  (`evidence/corpus/`): every VR string, VL 0/2/4 and 0xffffffff, implicit
  VR LE with transfer syntax, private creators, zero-length SQ. A batched
  gdb sweep over the real `dicomdump` (breakpoint on `vtkDICOMItem::Set`,
  printing `v.IsValid()`) parsed all 163 files: 1448 Set calls, **0 with
  `v.IsValid()==0`** (`evidence/sweep-gdb.out`). The W1 file-lane negative
  stands and is stronger; no file construct is invented.
- Reader-shaped check (advisory harness used `vtkDICOMReader`):
  `tools/reader-probe.cxx` compiled against both real builds. Batched gdb
  over all 163 corpus files: 1285 Set calls, **0 with `v.IsValid()==0`**
  (`evidence/reader-sweep-gdb.out`); direct ASan reader run over all 163:
  0 ASan reports (`evidence/reader-asan-sweep.out`). The sequence item is
  really parsed (nine Set calls per representative file), so this is a real
  negative rather than an early-exit artifact.
- Grade unchanged: rung 3 pinned functions + real-object ASan, rung 4 PARTIAL
  harness chosen bytes. No file-driven delete, no real `vtkDICOMReader` OOB,
  no wire path, no pointer/IP/control-flow/command, no rung 5, no witness
  verdict. Both examined real consumers are negative on the corpus; the
  remaining hypotheses are a version gap (advisory 9.5.2 vs pinned standalone
  0.8.17-53) or an unpublished file construct, which is not invented here.
  Replay still owed (tape #4256, material update #4262).



## W3 — crafted DICOM file drives real-reader heap OOB (2026-11-25 10:55Z)

The W1/W2 file-lane negatives were corpus-scoped. In the real pinned parser,
`Decoder::ReadElementValue` (:1291-1303) returns 0 with its local
`vtkDICOMValue` still invalid when an OB/OW element with vl==0xffffffff is
not followed by `(FFFE,E000)` or `(FFFE,E0DD)`. `ReadElements` skips the
short-read check for undefined length (:1624) and calls `Item->Set(tag,v)`
at :1645, i.e. the delete precondition. The earlier 163-file corpus always
placed the delimiter there, so it never hit this path.

`tools/make-undef-ob-dos.py` writes a 272-byte file whose sequence item
repeats that malformed construct twice in the exact order of the real-object
probe: fill tags 1..4, delete 3, insert 5, delete 5, insert 6,7,8. Results:

- ASan `vtkDICOMReader` on `evidence/undef-ob-chosen.dcm`: heap-buffer-
  overflow `WRITE of size 4`, 32 bytes past a 136-byte store from
  `vtkDICOMItem.cxx:70`, top frame `FindDataElementOrInsert` :195 via `Set`
  :295 via `ReadElements` `vtkDICOMParser.cxx:1645` via
  `vtkDICOMReader::RequestInformation` :741
  (`evidence/asan-file-reader-chosen.out`, rc 1). Real `dicomdump` faults too.
- Plain gdb: final `Set` writes chosen key `0x4841434b` at slot 5 of the
  four-slot store (`evidence/gdb-file-chosen.out`), after which the process
  SIGSEGVs. Identical bytes on the real fix `bcc8b26` reader are clean
  (rc 0); a benign corpus file on the vulnerable reader is clean (rc 0).
- `sh tools/replay-file-path.sh` = `REPLAY_FILE_PATH_OK`.

Grade: rung 3 in the real reader from crafted file bytes; rung 4 chosen bytes
at a chosen offset from file bytes, with a plain process crash. No wire or
request path, no pointer/IP/control-flow hijack, no command, no rung 5, no
witness verdict. Advisory 9.5.2 vs pinned standalone 0.8.17-53 version gap
remains UNKNOWN; the construct above is demonstrated on the pinned build.


## W4 — plain-build crash site, stale OOB pointer not file-controlled (2026-11-25 11:42Z)

The plain crash after the chosen-byte OOB write was localized with gdb
(`evidence/gdb-oob-pointer.out`). At the final insert the slot-5 element
carries stale `Value.V = 0x1e00000500000001`; the following real `Set` faults
decrementing that pointer in `vtkDICOMValue::operator=` (`Value.h:426` via
`ReferenceCount.h:50`, `this=0x1e00000500000001`, unmapped). Stack: `Set`
`vtkDICOMItem.cxx:297` ← `ReadElements` `vtkDICOMParser.cxx:1645`. This is the
plain SIGSEGV, not a destructor.

A bounded control test (`evidence/oob-pointer-invariance.txt`) generated a
variant file where a 2-byte US element becomes a 32-byte OB value of distinct
bytes (272 → 305 bytes). The store moved by 0x40, but the stale `Value.V` word
stayed byte-identical and the bytes are absent from both crafted files. The
fatal pointer is allocator-derived stale data, not file-chosen: pointer
control through this element is NOT OBSERVED (UNKNOWN).

Grade unchanged from W3: rung 3 in the real reader from file bytes; rung 4
file-chosen bytes at the chosen OOB slot with a plain crash. No pointer or IP
control, no command, no wire path, no rung 5. Witness verdict still UNKNOWN
(replay offer #4276 unanswered; witness wake RED). Advisory 9.5.2 vs pinned
standalone 0.8.17-53 version gap remains UNKNOWN.

## W5 — grooming and wire-path negatives (2026-11-25 13:26Z)

- Clean-archive replay from `HEAD`: fresh `git archive HEAD
  lab/frontier/vtkdicom2shell` → `sh harness/run-all.sh` = 14 PASS / 0 FAIL
  (GCC and Clang), rc 0.
- Root-level grooming bounded negative: twelve variants added a 0x4a-filled
  OB value of length 0/16/32/64/96/112/120/128/136/160/256/512 before the
  crafted SQ while leaving the item bytes unchanged. Real plain reader under
  gdb reached slot 5 at n=5 in every case with the identical stale pointer
  `e->Value.V = 0x1e00000500000001`; the store moved but the pointer word did
  not change or contain any 0x4a byte (`evidence/root-groom-negative.txt`).
  Together with W4's nine in-item value lengths, simple DICOM-value grooming
  is negative on both allocation paths. Pointer control is NOT OBSERVED
  (UNKNOWN), not proven impossible.
- Wire-path negative: the pinned tree has no socket/listen/accept/DIMSE or
  HTTP server and no network consumer of `vtkDICOMReader`; every in-tree
  consumer is a file→file/file→image CLI tool. There is no lab-observable
  request/wire path to these bytes. Rung 5 would require inventing a
  third-party server, which is outside the plant's lab and evidence rules.
- Grade unchanged: rung 3 in the real reader from crafted FILE bytes, rung 4
  file-chosen tag bytes at the chosen OOB slot with a plain crash. No pointer
  or IP control, no command, no wire path, no witness verdict (offer #4276
  unanswered; witness wake was activating at 13:22Z). Advisory 9.5.2 vs
  pinned standalone 0.8.17-53 gap remains UNKNOWN.

## W6 — exact VTK 9.5.2 bundled source replay (2026-11-25 18:03Z)

- Version gap closed at source level: VTK v9.5.2's
  `Remote/vtkDICOM.remote.cmake` fetches dgobbi/vtk-dicom at tag
  `d29a996ab2a49375a59cef5e381c1c25185ffa50` (2024-11-02). Its
  `vtkDICOMItem.cxx` sha256 `c53664ede...` differs from the vulnerable parent
  pin only by copyright year and two dictionary lookup/ordering functions;
  the six functions carrying the count desync and OOB write are unchanged.
  The exact 9.5.2 parser has the same undefined-length OB error exit and
  short-read exemption before `Item->Set` (see evidence file for line maps).
- Built that exact commit locally against the lab's VTK 9.1 deps. The
  advisory-shaped `vtkDICOMReader` probe on `evidence/undef-ob-chosen.dcm`
  gives ASan `WRITE of size 4`, 32 bytes past a 136-byte store, top frame
  `FindDataElementOrInsert` `Item.cxx:195` via `Set` :295, with a clean safe
  corpus control. Plain build: rc 139 and gdb `OOBWRITE key=4841434b n=5
  slot=5` before the SIGSEGV. Evidence and commands:
  `lab/frontier/vtkdicom2shell/evidence/vtk952-version-gap.txt`,
  `vtk952-asan-reader-attack.out`, `vtk952-gdb-chosen.out`.
- Bounded negative: that source's `dicomdump` CLI does not reach the parser
  on these bytes (its directory scan rejects the file, rc 0). The fixed
  control remains the W1-W5 `bcc8b26` build; no 9.5.2+fix build was made.
- Grade unchanged: rung 3 + rung 4 PARTIAL on the advisory's exact code;
  no pointer/IP/control-flow, no command, no wire path, no witness verdict.
  Vendor June-patch bytes remain UNKNOWN; VTK 9.6.0/9.6.1 still pin a
  vulnerable `Item.cxx` whose sha256 equals the vulnerable parent.

## W7 — predecessor-item grooming: two-state stale header, negative (2026-11-25 18:38Z)

W4/W5 called the stale OOB `Value.V` word byte-identical across their
variants. That invariance is variant-scoped, not global: preceding sibling
items inside the same crafted SQ change it in a bounded, two-state way.
`tools/make-preceding-item-variant.py` adds N well-formed items (PLEN
0x4a-filled OB elements each) before the crafted item; `tools/oob-word.gdb`
prints slot 5 at `Item.cxx:195` (`evidence/predecessor-item-groom-negative.txt`).

- PLEN 1-4 / N=0: `e+8(V)=1e00000500000001`, as in W4/W5.
- PLEN >=5 (N>=1): `e+8(V)=0d00000300000001`; N=8/PLEN=16 saturates there.
  A preceding top-level SQ attribute (1/2/4/8/16 elements) leaves the word
  unchanged at `1e000005...`.
- Both words decode as a stale `vtkDICOMValue::Value` header (`low32=00000001`
  reference count, small header bytes in `high32`), not a mapped address.
  Every variant still SIGSEGVs in `vtkDICOMReferenceCount::operator--`; no
  file byte appears at the dereferenced address and no pointer-shaped word
  was observed. File control of the stale pointer remains NOT OBSERVED
  (UNKNOWN), not proven impossible.
- Grade unchanged: rung 3 from crafted FILE bytes in the real reader, rung 4
  chosen tag bytes at the chosen OOB slot with a plain crash. No pointer/IP
  control, no command, no wire path, no witness verdict.

## W11 — stale OOB header decoded: structural pointer-control negative (2026-11-25 22:05Z)

W4/W5 tracked one stale OOB `Value.V` word, W7 refined it to two states. A
bounded VR sweep closes the question for this allocation class: with one
well-formed sibling item before the crafted item, PLEN 4/5 and VR in
US/SS/UL/FL/FD/OB/OW/UN, 15 completed runs produced a VR-dependent family of
words (e.g. US `1e00000500000001`, SS `1600000400000001`, UL
`1b00000700000001`, FL `0900000a00000001`, FD `0800000b00000001`, OB
`0d00000300000001`, OW `1100000500000001`), all with the same chosen key at
slot 5 and the same SIGSEGV in `ReferenceCount::operator--`. The command was
capped at 300 s during UN PLEN=5; that run and seven string VRs are UNKNOWN.

The words are exactly a stale `vtkDICOMValue::Value` header from the
preceding element: `low32` is `ReferenceCount=1`, byte 4 the VTK scalar type,
bytes 5/6 zero (character set, overflow), byte 7 the file-chosen VR enum
(`vtkDICOMValue.h:54-66`, `vtkDICOMVR.h:36-66`). Every observed value matches
that decode. VR is at most 0x24 and the type at most 0x0b, so the high half of
the dereferenced address cannot be mapped: pointer control through this stale
header is structurally closed for the observed allocation class, not merely
unseen. A different object type reusing that chunk was not observed and is
not excluded; see `lab/frontier/vtkdicom2shell/evidence/
vr-groom-header-negative.txt` for observations, decode and limits.

Grade unchanged: rung 3 (real-reader ASan OOB from crafted FILE bytes, also on
VTK 9.5.2's exact bundled source) and rung 4 PARTIAL (file-chosen tag bytes at
the chosen OOB slot, plain crash). No pointer/IP/control-flow, no command, no
wire path, no rung 5. Witness verdict UNKNOWN — W223 closed ctranslate2, no
vtkdicom replay; #4276/#4503 remain queued and the wake unit is inactive.
