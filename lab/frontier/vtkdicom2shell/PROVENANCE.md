# vtkdicom2shell lab provenance

- Claim: Cisco Talos TALOS-2026-2366 / CVE-2026-22879,
  https://talosintelligence.com/vulnerability_reports/TALOS-2026-2366 ,
  read-only provisioning on 2026-11-25. vtk-dicom 9.5.2,
  `vtkDICOMItem::FindDataElementOrInsert` / `NewDataElement`, CWE-129,
  CVSS:3.1 8.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`. Vendor patch
  release 2026-06-01, public release 2026-06-25.
- Upstream git: https://github.com/dgobbi/vtk-dicom.git . Vulnerable parent
  `2dd74234fdf4acf99eca2bef8a9907b24d0d18e8`; fix
  `bcc8b2676559ad3c66feb6dbe9038967defe54a5` ("Fix vtkDICOMItem corruption
  causing OOB write", explicitly `Ref: TALOS-2026-2366 / CVE-2026-22879`).
  The advisory's June patch date precedes this August upstream commit; the
  commit is the source-bound fix control, not an advisory-confirmed date.
- Verbatim pins in `pins/`:
  - `vtkDICOMItem-vuln.cxx` sha256
    `2814380a5034e4feb43a5795b1eb1c56e3f9287cfffc7973a38d94683147a02b`
    (`git show 2dd74234:Source/vtkDICOMItem.cxx`).
  - `vtkDICOMItem-fixed.cxx` sha256
    `c31c12bc707d22c06756e69b086eea0116bd9a5da19ba853a42ef04d152d31ab`
    (`git show bcc8b26:Source/vtkDICOMItem.cxx`).
  - `vtkDICOMDataElement.h` sha256
    `0f05d4f57ea39642b4ec64fd8b933f9153dbc0924c7049f4098cf33beb6a4721`
    (vulnerable parent; establishes the real field order).
- `harness/pinned-vuln.inc` and `harness/pinned-fixed.inc` are byte-identical
  line extracts from the two pinned `vtkDICOMItem.cxx` files (six disjoint
  line ranges each: `NewDataElement`, `FreeList`, `CopyList`,
  `CopyDataElements`, `FindDataElementOrInsert`, `Set(tag, value)`), verified
  with `diff` against the pinned files. `harness/common.h` supplies only
  stand-in dependency classes (tag, value, data element, VR, character set)
  with the real data-element field order; it does not reimplement the bug.
- `harness/main.cxx` is the driver; `harness/run-all.sh` builds GCC and
  Clang ASan/plain lanes and checks exactly 14 assertions. Result at staging:
  14 PASS / 0 FAIL. Every run is local; no external system was probed.
- `upstream/` is a local clone used only to extract the pins; it is ignored.

- Advisory version bound (W6): VTK v9.5.2's
  `Remote/vtkDICOM.remote.cmake` (read-only fetch from Kitware/VTK) pins
  `GIT_TAG d29a996ab2a49375a59cef5e381c1c25185ffa50`, already present in
  the local `upstream/` clone (2024-11-02, "Bump the version number to
  0.8.17"). That commit's `Source/vtkDICOMItem.cxx` sha256 is
  `c53664edef2e5a7fa99237ef5a7b8e0eb62f371b289cca3cfda34e7cb44ee35c`;
  its `Source/vtkDICOMParser.cxx` sha256 is
  `60e4d38c9ef01c8d8f788274c8fd8edbfda6fca4ca151a8622e65fe9c8f70cd6`.
  Exact-source build, ASan, gdb and controls:
  `evidence/vtk952-version-gap.txt`. VTK 9.6.0/9.6.1 pin
  `d1e25090f354542d7bd85c08ee36d8dc22bbbcd8`, whose `Item.cxx` sha256
  equals the vulnerable parent pin.
