# vtkdicom2shell — admitted status (2026-11-25 08:35Z)

## 2026-11-25 11:42Z — W4 plain-build crash site; stale OOB pointer not file-controlled

- The plain-build SIGSEGV after the chosen-byte OOB write was localized. gdb
  (`evidence/gdb-oob-pointer.out`): the final insert at slot 5 leaves a stale
  `Value.V` word `0x1e00000500000001` in the OOB element; the very next real
  `vtkDICOMItem::Set` dereferences it in `vtkDICOMValue::operator=`
  (`Value.h:426`) via `vtkDICOMReferenceCount::operator--` (`ReferenceCount.h:50`,
  `this=0x1e00000500000001`, unmapped). Stack: `Set` `Item.cxx:297` ←
  `ReadElements` `Parser.cxx:1645`. The crash is the stale-pointer decref in
  `Set`, not a later destructor.
- Bounded control test (`evidence/oob-pointer-invariance.txt`): a variant file
  replaces a 2-byte US element with a 32-byte OB value of distinct bytes
  (272 → 305 bytes). The store moved 0x40 bytes, but the stale `Value.V` word
  stayed byte-identical `0x1e00000500000001`, and those bytes do not occur in
  either crafted file. The fatal pointer is allocator-derived stale data, not
  file-chosen. Pointer control through this OOB element: NOT OBSERVED (UNKNOWN).
- Grade unchanged: rung 3 from crafted file bytes in the real reader, rung 4
  chosen tag bytes at the chosen OOB slot with a plain crash. No file control
  of the dereferenced pointer, no IP/control flow, no command, no wire path,
  no witness verdict (witness wake still RED, replay offer #4276 unanswered).

## 2026-11-25 10:14Z — W2 broad file-lane negative (no invalid value source)

- Source walk of the real vulnerable parser (`vuln-src/Source/`, `:raw`):
  `vtkDICOMItem::Set` deletes iff `!v.IsValid()`; `ReadElements` passes a
  default-invalid `vtkDICOMValue v` to `ReadElementValue`, which has a case
  for every valid VR type (even zero-length allocations are valid). The
  only unhandled type is `VTK_VOID` (XX/OX/XS), but unrecognised explicit VR
  strings decode to XX and are replaced by `FindDictVR`, which resolves
  XS->US/SS and OX->OB/OW. Empty SQ and undefined-length paths also produce
  valid values. No invalid-value source found in the ordinary parse path.
- `tools/make-corpus.py` generated 163 crafted sequence-item files
  (`evidence/corpus/`): all VR strings, VL 0/2/4 and 0xffffffff, implicit
  VR LE with transfer syntax, private creators, zero-length SQ. Batched gdb
  over the real `dicomdump` (breakpoint on `vtkDICOMItem::Set`, printing
  `v.IsValid()`) parsed all 163: 1448 Set calls, **0 with `v.IsValid()==0`**
  (`evidence/sweep-gdb.out`). Advisory confirms a delete is required but
  publishes no file construct; none is claimed here.
- Reader-shaped check (the advisory harness used `vtkDICOMReader`):
  `tools/reader-probe.cxx` compiled against both real builds; batched gdb
  over all 163 files found 1285 Set calls, **0 with `v.IsValid()==0`**
  (`evidence/reader-sweep-gdb.out`), and a direct ASan reader run over all
  163 files found 0 ASan reports (`evidence/reader-asan-sweep.out`). The
  sequence item is really parsed (nine Set calls per representative file),
  so this is a real negative, not an early-exit artifact.
- Grade unchanged: rung 3 pinned functions + real-object ASan; rung 4 PARTIAL
  harness chosen bytes. No file-driven delete, no real-reader OOB, no wire
  path, no pointer/IP/command, no witness verdict. Both examined real
  consumers are negative on the corpus; remaining hypotheses are a version
  gap (advisory 9.5.2 vs pinned standalone 0.8.17-53) or an unpublished file
  construct. Witness replay still owed (tape #4256, material update #4262).


## 2026-11-25 09:48Z — W1 real build, real-object ASan, file-lane negative

- Clean-archive replay 14 PASS / 0 FAIL; three pin hashes match provenance.
- Real vulnerable vtk-dicom built against lab-local VTK 9.1 debs: real
  `libvtkDICOM-9.1.a`, real `dicomdump`, ASan build. Crafted sequence-item
  files reached real `vtkDICOMItem::Set`, but gdb showed `v.IsValid()==1`
  for every attempted delete element (empty SQ, invalid VR, private tag):
  no file-driven count decrement and no ASan report. File trigger OPEN.
- Real-object API probe: ASan `WRITE of size 4` one past the real 4-slot
  store at `vtkDICOMItem.cxx:195` via `Set` →
  `FindDataElementOrInsert`; the same probe on the real `bcc8b26` build is
  clean (count 6, no ASan). Rung 4 mechanics on real objects, NOT a file or
  wire trigger. No pointer/IP/control-flow/command, no rung 5, no witness
  replay. Evidence: `lab/frontier/vtkdicom2shell/evidence/`.

## 2026-11-25 08:35Z — ADMITTED under standing #6 (145th route)

- Verified staged claim, charter, wall, lab and pre-existing window 153; no
  second window created.
- Added the hy4-flash `max_parallel: 3` route in `.mishe-tauftauf/engine/routes.json`
  and both resolver keys in `.mishe-tauftauf/resolvers.json`; re-read and
  JSON-parsed both files after the edit.
- EXACT full-flag sync from `docs/runtime-pin.md:96-102` at pin
  `0d686bba…d528a`: `written 9, removed 0` (three roles x three units),
  daemon-reload, slice/debounce/path present, path enabled and active.
- Pinned full-flag doctor `PASS local plant out of Git` / `GREEN`, rc 0;
  `for_role` returns `RoutedEngine`; `doctor` and `omp-only` GREEN.
- Grade unchanged: rung 3 pinned functions / rung 4 PARTIAL chosen bytes at
  harness-groomed offsets, harness 14 PASS / 0 FAIL; no real build, DICOM
  file/wire through a real reader, pointer/IP/control-flow, command, r5 or
  witness verdict.

The staged record below is preserved as the pre-admission evidence.

## 2026-11-25 07:56Z — STAGED + HANDED OFF

- Claim: CVE-2026-22879 / TALOS-2026-2366, vtk-dicom 9.5.2, CWE-129,
  CVSS:3.1 8.1 AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H. Vendor patch 2026-06-01;
  source-bound fix commit `bcc8b26` cites the CVE explicitly, vulnerable
  parent `2dd74234`.
- Lab: `lab/frontier/vtkdicom2shell/`; pins, provenance, verbatim function
  extracts, harness and evidence. `sh harness/run-all.sh`: 14 PASS / 0 FAIL,
  GCC and Clang, ASan/plain/fixed/safe lanes.
- Observed: ASan heap-buffer-overflow `WRITE of size 4` at
  `pinned-vuln.inc:127` (`e->Tag = tag;`) in
  `vtkDICOMItem::FindDataElementOrInsert()` via `Set()`. Plain: chosen
  `0x4841434b` / `0x42424242` at groomed heap store+160 / store+168; fixed
  and no-delete controls clean.
- Grade: rung 3 pinned functions / rung 4 PARTIAL chosen bytes at a
  harness-groomed offset. Stand-in dependency classes; no real vtk-dicom
  build, no DICOM file/wire through a real reader, no pointer or control-flow
  hijack, no command execution, no witness verdict. Rung 5 NOT CLAIMED.
- Deliverables: `reports/frontier-vtkdicom2shell.md`, this status, charter,
  seed wall and inner two-pane window 153 with registry entry and operator /
  witness DMs.
- Next for the target mind: clean-archive replay; real vtk-dicom/VTK build
  with crafted DICOM sequence; witness replay before any rung-4 publication.

## 2026-11-25 10:55Z — W3 crafted FILE drives real-reader OOB (chosen bytes)

- Cause of the W1/W2 file-lane negative found: corpus case B always placed
  `(FFFE,E0DD)` immediately after an undefined-length OB/OW element, the one
  layout that keeps the local `vtkDICOMValue` valid. `vtkDICOMParser.cxx`
  :1291-1303 returns 0 with `v` still invalid when the following 8 bytes are
  not an item/delimiter tag; `ReadElements` skips the short-read check for
  vl==0xffffffff (:1624) and still calls `Item->Set(tag, v)` (:1645) — a
  delete. W1/W2 file negatives are corpus-scoped, not universal.
- `tools/make-undef-ob-dos.py` crafts a 272-byte sequence-item file mirroring
  the real-object probe: fill 1..4, delete 3 with a malformed OB (0008,0003),
  insert 5, delete 5 with a second malformed OB, insert 6,7,8. Files:
  `evidence/undef-ob-dos.dcm` and `evidence/undef-ob-chosen.dcm` (final tag
  0x4841434b).
- ASan real `vtkDICOMReader` on chosen file (rc 1): heap-buffer-overflow
  `WRITE of size 4`, 32 bytes after a 136-byte region allocated at
  `vtkDICOMItem.cxx:70`; top frame `FindDataElementOrInsert` :195 via `Set`
  :295 via `ReadElements` `vtkDICOMParser.cxx:1645` via
  `vtkDICOMReader::RequestInformation` :741
  (`evidence/asan-file-reader-chosen.out`). Real `dicomdump` on the same
  bytes also faults (`evidence/asan-file-dicomdump.out`).
- Plain-build gdb (`evidence/gdb-file-chosen.out`): final Set writes
  `tag=4841,434b key=4841434b` at slot 5 of a 4-slot store (n=5), then the
  process SIGSEGVs. Fixed `bcc8b26` reader on identical bytes: rc 0, clean
  (`evidence/asan-file-reader-fixed-chosen.out`); safe corpus input on the
  vulnerable reader: rc 0, clean (`evidence/asan-file-safe.out`).
- One-command replay `sh tools/replay-file-path.sh` = `REPLAY_FILE_PATH_OK`.
- Grade: rung 3 ASan-confirmed from crafted FILE bytes in the real reader;
  rung 4 chosen tag bytes at the chosen OOB slot from FILE bytes with a plain
  process crash. Still no wire/request path, no pointer/IP/control-flow
  hijack, no command, no rung 5. Witness verdict UNKNOWN (wake service RED).
