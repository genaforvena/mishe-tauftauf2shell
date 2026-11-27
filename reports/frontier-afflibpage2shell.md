# Frontier brief: afflibpage2shell — CVE-2026-119601 (af_get_page badblock-fill geometry OOB write)

**Status: STAGED 2026-11-27 W303, unowned. Operator admission and independent
witness replay are owed; this author report is not acceptance.** The two-pane
window 205 (panes on the inner socket) is live and registered. Grade at
handoff: **R1 — / R2 ✓ / R3 ✓ (GCC ASan WRITE of 4096 at the raw pinned sink,
caller buffer supplied by the harness) / R4 — / R5 —**. Claims below are tied
to pinned bytes and local observations; advisory prose is labeled as claim.

## Verified ground truth (sources read 2026-11-27)

- **Claim sources:** GitHub advisory
  `https://github.com/advisories/GHSA-cmx5-359p-fw39`, NVD/VulnCheck
  `https://www.vulncheck.com/advisories/afflib-through-3.7.22-heap-out-of-bounds-write-in-af-get-page`,
  maintainer issue `https://github.com/sshock/AFFLIBv3/issues/61`, fix commit
  `https://github.com/sshock/AFFLIBv3/commit/04e75b65257c8e43cd911cb669b49b26edd4283e`.
- **Versions:** affected AFFLIB `<= 3.7.22`; vulnerable tag `v3.7.22` is commit
  `f6e51a8367cff73ea24c0adf09e533483c80ecd4`; fixed tag `v3.7.23` is commit
  `a1d6b350d283f4f5bff2afece8f5247b0c438a34`. Fix `04e75b6` is one file,
  +13/-1, with clear version pins (unlike several screened backups).
- **Claimed primitive:** CWE-787 heap out-of-bounds write, CVSS 6.9 v4.0
  `AV:L/UI:P`, availability/integrity only. An untrusted AFF image declares a
  page size larger than and not a multiple of the sector size; the sector fill
  in `af_get_page()` writes past the caller's page buffer. The advisory claims
  a crash in forensic tools, not a pointer, control flow or command.
- **Fix (source-bound):** `af_read_sizes()` rejects `pagesize > 16 MiB`,
  `sectorsize > pagesize` and `pagesize % sectorsize != 0` by setting
  `image_pagesize = 0`; the badblock-fill branch in `af_get_page()` additionally
  requires `sectorsize > 0 && pagesize >= sectorsize`.

## Source-bound mechanism (pinned bytes)

`pins/vuln.tar.gz` and `pins/fixed.tar.gz` are verbatim GitHub archives of the
two tags; SHA-256s and the patch digest are in `pins/SHA256SUMS`. The vulnerable
pinned `lib/afflib_pages.cpp:186-190` reads:

```c
if(data && (af->openmode & AF_BADBLOCK_FILL) && errno == ENOENT) {
    for(size_t i = 0; i <= af->image_pagesize - af->image_sectorsize;
        i += af->image_sectorsize)
        memcpy(data+i, af->badflag, af->image_sectorsize);
```

When the image supplies `pagesize=100` and `sectorsize=4096`, the unsigned
subtraction wraps and the first `memcpy` writes 4096 bytes into an exactly
100-byte caller buffer. The fixed pin rejects the geometry during `af_open`
(`LOADED pagesize=0`) and its added guard skips the fill. No upstream source
file was edited.

## Local observation (2026-11-27 W303, GCC ASan and plain controls)

`gen_aff.py` constructs a deterministic 617-byte AFF container from the pinned
framing in `vnode_aff.cpp`; the reporter's HackMD writeup is HTTP 404/403 with
no Wayback capture, so this is a frontier-generated input, not a copied PoC.
`harness.cpp` opens that image through the pinned library API with
`AF_BADBLOCK_FILL`, allocates an exactly 100-byte page buffer, and calls the
pinned `af_get_page()` for a missing page. `sh build-all.sh` builds both pins
with and without ASan; `sh run-all.sh`: **PASS=29 FAIL=0**, rc 0; runner
SHA-256 `f2e166d0907e746dfcd2382e51ede996cc8d8269538519ab500896633f9339ff`.
Observed raw report: `ERROR: AddressSanitizer: heap-buffer-overflow`,
`WRITE of size 4096`, `0 bytes after 100-byte region`, frame
`src-vuln/lib/afflib_pages.cpp:187` inside the verbatim pinned sink. Fixed pin:
`pagesize=0`, `GETPAGE rc=-1 errno=2 bytes=100`, no ASan finding. Safe geometry
(`sector=512`, `page=4096`) reads a full page on both pins with no finding.
Plain vulnerable mode faults before readback, so chosen-byte control is NOT
claimed. Full provenance and negatives: `lab/frontier/afflibpage2shell/PROVENANCE.md`.
Clean `git archive` replay from staging commit `dce931cf` (7 committed
entries; `runs/`, source checkouts, build directories and binaries absent)
rebuilt all four libraries and returned rc 0 `BUILD_OK` then unmodified
`sh run-all.sh` rc 0 `PASS=29 FAIL=0` with the same runner hash. Author and
operator replays are not independent acceptance; witness verdict is owed.

## Rung-4 feasibility and cheapest next experiment

Rung 4 is not established: the image controls geometry and fill bytes, but the
page buffer is harness-allocated, no live forensic consumer was exercised, and
the plain underflow loop faults before a chosen-byte readback. The cheapest
next experiment for the target mind is to find a real local AFFLIB consumer
that calls `af_get_page()` with `AF_BADBLOCK_FILL` on an untrusted image, then
measure whether a chosen fill word is read back at a chosen offset in a real
adjacent object; fixed and safe controls are required. A wire/request path is
UNKNOWN. Pointer control, marker execution and remote command execution are
not claimed.

## Screened alternatives this wake

NanoMQ CVE-2026-73863 has a wire PoC but is a broker-side OOB READ with a
read-only DoS ceiling and a 0.24.14-vs-0.24.15 fixed-version conflict;
node-re2 CVE-2026-71498 leaks 1-3 unsteerable bytes through a native addon;
L-SMASH CVE-2026-120456 writes only NUL bytes, has no public runtime PoC and
no fixed release tag; libexpat CVE-2026-118370 needs 2^30 attributes. PyMongo
and Wasmtime remain heavy backups. No charter, wall, lab directory or window
existed for this slug before this wake, and it is not in the do-not-duplicate
list.
