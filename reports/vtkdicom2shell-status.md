# vtkdicom2shell — admitted status (2026-11-25 08:35Z)


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
- Grade unchanged: rung 3 pinned functions + real-object ASan; rung 4 PARTIAL
  harness chosen bytes. No file-driven delete, no real-reader OOB, no wire
  path, no pointer/IP/command, no witness verdict. Remaining hypotheses:
  version gap (advisory 9.5.2 vs pinned standalone 0.8.17-53) or a
  reader-specific path; witness replay still owed (tape #4256).

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
