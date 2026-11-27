# afflibpage2shell — staged status (2026-11-27)

Staged by frontier W303 from CVE-2026-119601 / GHSA-cmx5-359p-fw39 (CWE-787,
CVSS 6.9 v4.0, affected `<= 3.7.22`, `AV:L/UI:P`). Vulnerable tag `v3.7.22`
is commit `f6e51a8367cff73ea24c0adf09e533483c80ecd4`; fixed tag `v3.7.23` is
commit `a1d6b350d283f4f5bff2afece8f5247b0c438a34`; verbatim one-file fix
`04e75b65257c8e43cd911cb669b49b26edd4283e` is pinned at
`lab/frontier/afflibpage2shell/pins/fix.patch`. The two-pane window 205 was
created on the inner socket and registered once with no duplicate CVE/GHSA or
sink lane.

A crafted 617-byte AFF image declares `pagesize=100` and `sectorsize=4096`.
The pinned vulnerable `af_get_page()` badblock-fill loop at raw
`lib/afflib_pages.cpp:186-190` subtracts the larger sector size from the page
size, wraps, and its first `memcpy` writes 4096 bytes into a 100-byte caller
buffer. GCC ASan: `heap-buffer-overflow`, `WRITE of size 4096`, 0 bytes after
the 100-byte region, pinned frame `afflib_pages.cpp:187`. The fixed pin sets
`image_pagesize=0` at open and returns `rc=-1 errno=2` with no ASan finding;
safe geometry reads a full page on both pins. Plain vulnerable mode faults
before any chosen-byte readback.

Registered grade at handoff: **R1 — / R2 ✓ / R3 ✓ / R4 — / R5 —**. R3 is an
invalid write in the verbatim pinned sink with the caller buffer supplied by
the harness. No live AFFLIB consumer, chosen-offset readback, pointer,
wire/request path, marker or command was observed.

`sh build-all.sh && sh run-all.sh`: rc 0 `BUILD_OK` then `PASS=29 FAIL=0`.
Runner SHA-256 `f2e166d0907e746dfcd2382e51ede996cc8d8269538519ab500896633f9339ff`.
Clean-archive replay from `git archive dce931cf lab/frontier/afflibpage2shell`
(7 entries, no `runs/`, checkouts, builds or binaries) rebuilt both pins and
returned rc 0 `BUILD_OK` then unmodified `sh run-all.sh` rc 0 `PASS=29 FAIL=0`
with the same runner hash above.
Operator admission under standing #6 and independent witness replay are owed;
this author report is not acceptance.

Brief: `reports/frontier-afflibpage2shell.md`. Harness provenance and
negatives: `lab/frontier/afflibpage2shell/PROVENANCE.md`.
