# Frontier brief — HTSlib CRAM v4 XPACK block_by_id OOB pointer write (Htslib2Shell)

**Status: frontier find, brief + harness COMPLETE (2026-11-21 ~16:00Z);
UNADMITTED, witness replay and operator admission pending. Rungs 2/3 are
ESTABLISHED on verbatim-pinned HTSlib 1.23.1: ASan reports `READ of size 8` at
`cram/cram_codecs.c:1378` and `WRITE of size 8` at `:1388`, 8 bytes past a
4096-byte `block_by_id` region; the unsanitized pinned library performs the
same out-of-bounds pointer write without a sanitizer (rung 1, sink-level).
Rung 4 is INSTRUMENTED only: no CRAM file, no parser path from file bytes, no
web-facing consumer, no chosen pointer value, no live neighbour object, no
control-flow diversion or execution was observed. All stay UNKNOWN.
Trace `sha256=40f5992496d13bfc3b575625a5b6bb6e8dfbd1eb397b8b5b25ced7458c04f464` (9 PASS / 0 FAIL, `bash run.sh out-final`).
Seed wall `.mishe-tauftauf/walls/htslib2shell.md`. Two-pane window
`htslib2shell` index 62 on the inner socket; pane processes started
15:58:33/34Z, registry written 15:58:58Z, and frontier re-captured the top
pane at 16:01Z. The earlier 16:00Z creation claim was approximate and the
registry `created` field now records 15:58Z from observed mtimes/pane PIDs.
Scoped harness/pins commit `bced853`; clean `git archive bced853` replay gave
the same 9 PASS / 0 FAIL and trace hash. Witness replay DM #996 and operator
admission DM #997 were sent at 15:59:42Z. Frontier re-ran `run.sh` from the
pinned tarballs at 16:01Z: 9 PASS / 0 FAIL and the identical trace hash; the
bottom pane is a live plant_view writing to that role's pane log.

## Verified ground truth (claim sources, 2026-11-21)

- **Advisory**: CVE-2026-62257 / GHSA-6q7c-m967-9v37, "HTSlib: Heap read and
  write overflow in HTSlib CRAM 4.0 decoder". MITRE record published and
  updated 2026-11-19T15:41:55.655Z (CNA GitHub, Inc.); GitHub advisory
  published 2026-07-09 by `daviesrob`; OSV published 2026-11-19T15:41:55Z,
  modified 2026-11-20T21:03:23Z. CWE-122, CWE-125, CWE-787. CVSS 4.0 8.8
  HIGH, `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N`.
  Claim: experimental CRAM v4 XPACK/XRLE decoders cache expanded block
  pointers at indexes beyond the always-512-element `slice->block_by_id`
  array; an index partially controlled by file data first causes an OOB read,
  then a NULL result causes allocation and an OOB pointer write; "may permit
  arbitrary code execution". Credit: Trail of Bits and Anthropic.
- **Versions**: affected `<1.21.2`, `1.22.0–1.22.2`, `1.23.0–1.23.1`; fixed
  in tagged releases **1.21.2, 1.22.3, 1.23.2 and 1.24**, with backports.
  Records: `https://www.cve.org/CVERecord?id=CVE-2026-62257`,
  `https://cveawg.mitre.org/api/cve/CVE-2026-62257`,
  `https://api.osv.dev/v1/vulns/CVE-2026-62257`,
  `https://github.com/samtools/htslib/security/advisories/GHSA-6q7c-m967-9v37`.
- **Fix**: three referenced commits —
  `d66a77dbf8f52f7f44efd7929a28b94bbfc17f2` (move the per-codec cache from
  `slice->block_by_id[512+codec_id]` into `expanded` members of the codec
  structs and stop incrementing `hdr->ncodecs`),
  `c0b50372ed133c650fa0a641607da5cde46bcd8c` (int32 overflow and nbits==0
  guards), and `a3e8dca14dcfdc6167281721ede6d6ecd3395bad` ("Remove CRAM v4.0
  support"). All three `.patch` bytes are pinned below. The 1.24 release has
  no XPACK/XRLE codec symbols at all.
- **Pins**: ten artifacts with exact SHA-256 in
  `lab/frontier/htslib2shell/src/SHA256SUMS`; digest/URL/line table in
  `lab/frontier/htslib2shell/PROVENANCE.md`. Vulnerable is the tagged release
  1.23.1 (`f8a3f36e…`), fixed is the tagged release 1.24
  (`28a8de19…`), not a floating branch.

## Source-bound mechanism (raw pinned bytes, 1.23.1 release tarball)

- `cram/cram_structs.h:373-374` documents `ncodecs` as the "Total codec
  count, used for index to block_by_id for transforms".
- `cram/cram_io.c:4620` allocates `s->block_by_id = calloc(512,
  sizeof(s->block[0]))` — 512 pointer slots, indexed 0..511.
- `cram/cram_codecs.c:3882`, inside the real `cram_decoder_init`, executes
  `r->codec_id = hdr->ncodecs++` for every successfully constructed codec,
  including each sub-codec of XPACK/XRLE; a compression header with enough
  declared codecs drives this counter past 511. The harness observed
  `codec_id=1` from `ncodecs=0` in a single XPACK-with-EXTERNAL-sub-codec
  construction (the sub-codec consumed id 0).
- `cram/cram_codecs.c:1378` in `cram_xpack_decode_expand_char` reads
  `cram_block *b = slice->block_by_id[512 + c->codec_id];` — with `codec_id=1`
  that is index 513, one pointer past the allocation. If the read yields
  non-NULL the function returns early; if NULL, `:1388` writes
  `b = slice->block_by_id[512 + c->codec_id] = cram_new_block(0, 0);` — an
  out-of-bounds 8-byte pointer store. `cram_xrle_decode_expand_char` has the
  identical pattern at `:2075` and `:2079` (not exercised here).
- Fixed-side raw bytes: `d66a77d` replaces both cache sites with codec-local
  `expanded` members and deletes `r->codec_id = hdr->ncodecs++`; `a3e8dca`
  removes CRAM v4 support. The harness observes 1.24 returning NULL for codec
  51 with `Unimplemented codec of type ?`.

## Lab evidence (`lab/frontier/htslib2shell/`, `bash run.sh out-final`)

9 PASS / 0 FAIL, rc 0, trace `sha256=40f5992496d13bfc3b575625a5b6bb6e8dfbd1eb397b8b5b25ced7458c04f464` over the ordered PASS lines
(no PIDs, addresses or paths). All ten pins verify with
`cd src && sha256sum -c SHA256SUMS`. `run.sh` rebuilds both tagged releases
from the pinned tarballs with no network access.

- **Rung 1 (sink-level, unsanitized)** — the plain pinned 1.23.1 build runs
  the real `cram_decoder_init`/`cram_xpack_get_block` path to completion with
  no sanitizer; the out-of-bounds slot holds an adjacent-heap junk pointer
  `0x1011` after the write. No signal or crash was observed, so no crash
  claim is made.
- **Rung 2 (accounting)** — the real dispatch assigned `codec_id=1`, giving
  cache index 513 into a 512-slot array; the harness printed the exact
  `512+codec_id=513 vs 512 slots` accounting.
- **Rung 3 (ASan)** — `heap-buffer-overflow`, `READ of size 8` in
  `cram_xpack_decode_expand_char cram_codecs.c:1378` ← `cram_xpack_get_block
  :1449` ← harness; `WRITE of size 8` at `:1388` on the same path; both at an
  address "8 bytes after 4096-byte region". A third read at `:1450` follows.
  Recovered-mode ASan (`-fsanitize-recover=address`, `halt_on_error=0`) let
  the OOB write execute after the OOB read, matching the advisory's
  read-then-write sequence. Logs: `out-final/asan.log`.
- **Fixed side** — same harness on tagged 1.24: codec 51 is rejected,
  `Unimplemented codec of type ?`, no codec allocation, clean shell exit.
  Log: `out-final/fixed.log`.
- **Stand-ins (honest)** — the 512-pointer array is allocated with the exact
  pinned `calloc(512, sizeof(...))` shape, but in the harness rather than
  inside `cram_read_slice`; `hdr->ncodecs` is set directly; the 7 XPACK
  parameter bytes and the in-bounds source block are harness-authored. No
  CRAM file bytes were parsed. Value `0x1011` and ASan address
  `0x521000001108` are observed, not chosen.

## Rung-4 feasibility assessment and ranking

This is a genuine OOB **pointer** store with a partially file-controlled
index and a tagged fixed release, but it is a **library-only file-parser
route**. Unlike wolfSSL's pre-auth DTLS path (admitted/deferred separately),
there is no listener, no network-facing consumer exercised here. CVSS
`AV:N` is an advisory claim about downstream deployments, not a lab
observation. Web-facing consumers of HTSlib (e.g. web services that decode
user-uploaded CRAM/BAM) are plausible but none was built, configured or
fed a crafted file in this lab. Ranked **below** the network-facing
candidates and at best rung 4 INSTRUMENTED without such a consumer:
chosen bytes at chosen offsets have not been demonstrated, nor has any
live object, pointer field or control-flow target been overwritten.

Cheapest next experiment for an admitted target mind: construct a real CRAM
v4 file whose compression header declares enough codecs to push
`hdr->ncodecs` (and hence `codec_id`) past 511 and uses XPACK at the boundary;
feed it to the pinned 1.23.1 `htsfile`/`samtools` decoder under ASan with a
gdb watchpoint on `slice->block_by_id[512]`, then check whether the OOB store
lands on a live heap object. Until that is observed, rung 4 stays
INSTRUMENTED and pointer/control-flow/execution stay UNKNOWN.

## Scope and boundaries

Local process only; all source fetching was read-only provisioning, no
probing of external systems, no traffic off loopback, no other plant's lane.
Negative result preserved: an earlier attempt with `nprior=512`
(`codec_id=513`, index 1025) produced no ASan report — the read landed in a
different live heap allocation and returned `0xbebebebebebebebe`; that is why
the committed repro uses `nprior=0` (index 513, immediate redzone) for a
deterministic ASan report. Witness re-runs this claim from a clean
`git archive` replay.
