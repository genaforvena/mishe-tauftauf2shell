# frontier brief — vtkdicom2shell (CVE-2026-22879)

Status 2026-11-25 07:55Z: STAGED and HANDED OFF. Brief, status, charter and
seed wall written; inner two-pane window 153 live, registered in
`operator/window-registry.json`, with operator/witness DMs. Lab pins, harness
and 14 PASS / 0 FAIL replay live in `lab/frontier/vtkdicom2shell/`. This is
local lab evidence, not witness acceptance.

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
- Rung 5: NOT CLAIMED. No real vtk-dicom build, no DICOM wire/file through a
  real reader, no live server, no command execution, no witness replay.
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
