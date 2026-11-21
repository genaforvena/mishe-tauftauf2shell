# Frontier brief — libIEC61850 MMS FileRead underflow (Iec618502Shell)

**Status: new frontier find, brief + harness COMPLETE (2026-11-21 ~13:49Z) —
pending independent witness replay and operator admission.** Rungs 1/2/3 are
ESTABLISHED in a real pinned library process over loopback: rung 3 is the ASan
report from the server, rungs 1/2 are the unauthenticated network trigger and
the observed length/state failure. Rung 4 is **UNKNOWN**: the staged file bytes
are chosen locally, but no chosen-byte readback at offsets in the live server,
real heap neighbour, pointer, control-flow diversion or execution was observed.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-49035 / CISA ICSA-26-204-06. CNA `icscert`, CVSS 3.1
  8.1 HIGH (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`) and CVSS 4.0 9.2 in the
  pinned CNA record; CWE-122/191 in the PoC/NVD material. CISA: "The affected
  product is vulnerable to a heap-based buffer overflow via a crafted MMS
  Initiate request. Remote code execution (RCE) has been demonstrated when
  ASLR is disabled." Affected `>=v1.0.0|<=v1.6.1`; fixed in released v1.6.2.
- **Fix**: commit `db35acf67bfdb4c5bdbcfb19b66529476bf72d21` adds
  `MMS_MIN_MAX_PDU_SIZE 128` and rejects small Initiate sizes; the pinned
  GitHub API JSON records both hunks. The vendor release v1.6.2 tag is pinned
  as a full source tarball.
- **Pins**: six SHA-256 pins in `lab/frontier/libiec61850/src/SHA256SUMS`,
  including both full source tarballs and the pinned public PoC tarball. The
  raw packet client is third-party GPL-3.0 code, invoked verbatim as a tool;
  details in `PROVENANCE.md`. The CISA HTML page returned HTTP 403 during
  provisioning, so the CISA prose above is a claim from the CNA/NVD records,
  not an independently pinned CISA byte snapshot.

## Source-bound mechanism (raw pinned bytes)

- Vulnerable commit `a1396111` `mms_association_service.c:359-363`: MMS
  Initiate `local-detail-calling` (tag `0x80`) is decoded into
  `self->maxPduSize` and only upper-clamped; value 1 is accepted.
- `mms_file_service.c:834` computes `uint32_t maxFileChunkSize = maxPduSize -
  20`; with 1 this wraps to `0xffffffed`. The `:840` guard
  `bytesLeft > maxFileChunkSize` is then false for every realistic file, so
  `:844` sets `fileChunkSize = bytesLeft` (the whole file).
- `mms_file_service.c:869-873` encodes the response header and calls
  `FileSystem_readFile(frsm->fileHandle, buffer + bufPos, fileChunkSize)` at
  `:872`. The destination is `sendBuffer`, a 65100-byte allocation at
  `iso_connection.c:47` / `:516`. Call chain from the ASan report: `:872` ←
  `mmsServer_handleFileReadRequest` `:896` ← real ISO server thread.

## Lab evidence (`lab/frontier/libiec61850/`, `bash run.sh <outdir>`)

7 PASS / 0 FAIL rc 0; two independent three-run groups both
`sha256=5a7bb6904856d6f8577c06958c66ff9b7721f550701257cf3b427a679bd9d1ce`.
Clean `git archive e6efd18 lab/frontier/libiec61850` replay into a fresh `/tmp`
directory gave the same 7 PASS / 0 FAIL rc 0 and the same digest.

- Loopback-only local process: stock ASan `server_example_files` built from
  the pinned vulnerable source on port 10110, raw MMS client from the pinned
  PoC connects to `127.0.0.1`, sends Initiate with size 1, FileOpen and
  FileRead of a 200000-byte staged file.
- ASan: `heap-buffer-overflow`, `WRITE of size 178157`, `0 bytes after
  65100-byte region` allocated at `iso_connection.c:516`; write frame
  `mms_file_service.c:872`, caller `:896`.
- Controls: maxPduSize 20 with the same large file and maxPduSize 1 with a
  200-byte file are ASan-clean.

**Fixed-side negative result (preserved):** released v1.6.2 was built with the
same flags. It rejects the Initiate (client sees the AARE failure byte `0x08`
instead of an InitiateResponse), but it stores `maxPduSize = 1` before the
reject and the raw client reuses the association; the FileRead still produces
the same ASan WRITE. This is a bypass observed in this harness, not proof that
a conforming client (which would stop on AARE failure) can bypass the fix.
The fixed build is therefore **not** a clean control on this route.

## Rung-4 feasibility assessment

Grade: rungs 1/2/3 ESTABLISHED in a real network-facing library process; rung 4
UNKNOWN. The staged file contains chosen `0x5a`/`0xa5` bytes, but this lab has
not read them back at chosen offsets past the live `sendBuffer`, nor identified
a live neighbour. Cheapest next experiment: gdb watchpoint on
`sendBuffer + 65100` in the ASan-free loopback service, with the staged file
pattern varied, then attempt ObtainFile staging so the bytes are remotely
chosen. The public RCE chain additionally needs ASLR off, non-PIE, writable
GOT and AArch64-specific offsets; none was run here.

## Next-candidate queue

- OpenJPEG OSV-2025-219 / GHSA-78g4-xqwv-q3g8: strong chosen-value write
  claim, but no tagged fixed release and PoC must be regenerated.
- wolfSSL CVE-2026-6679 (DTLS 1.3 ACK, fixed 5.9.1) and HTSlib
  CVE-2026-62257 (CRAM v4 pointer write, fixed 1.24 and backports): stateful
  paths, lower tractability.
- libexpat CVE-2026-77214 is an OOB READ, not this plant's write primitive.

## Scope and boundaries

Loopback only: one local server per case on unprivileged 127.0.0.1 ports,
no external probing, no Docker/RCE harness, no other plant's lane. Third-party
PoC code and both library trees are pinned verbatim; harness stand-ins and
exact source URLs are in `PROVENANCE.md`.
