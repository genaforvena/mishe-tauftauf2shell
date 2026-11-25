# vtkdicom2shell — lab status

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
