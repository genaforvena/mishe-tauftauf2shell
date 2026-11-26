# frontier-libarchivezippath2shell — STAGED: shipped-CLI ZIP writer chosen-byte heap WRITE (CVE-2026-45308)

Status: **STAGED in W284 (2026-11-26); rung-3 ASan WRITE confirmed through the
shipped `bsdtar` CLI with a locally crafted PAX tar; rung 4 NOT CLAIMED.**
The clean-archive runner `lab/frontier/libarchivezippath2shell/run-all.sh`
rebuilds both pinned releases from hashes and reported `RESULT PASS=40 FAIL=0`
at 19:01Z (`console.log`; see `PROVENANCE.md` for pins and traces). Charter,
seed wall, status report and two-pane window 193 (panes %390/%391 live) are
staged; operator admission and independent witness replay are owed.

## Claim source and scope

- Vendor GHSA `https://github.com/libarchive/libarchive/security/advisories/GHSA-xgqq-r5j8-3mch`
  (published 2026-08-24, Low, CVSS 3.1 `AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N`,
  CWE-787, CVE-2026-45308, credit Crypto-Cat). Claim: a pathname longer than
  65536 bytes in an archive that is re-packed as ZIP overflows the ZIP writer's
  fixed 64 KiB central-directory segment; reproduces on released `v3.8.7` and
  master `aca8b0d3`; `bsdtar --format=zip -cf out.zip @evil.tar` is the given
  reachability example. The finder explicitly claims memory corruption only,
  no code execution.
- Affected `<= 3.8.7`; patched `>= 3.8.8`. Pinned vulnerable tarball
  `https://github.com/libarchive/libarchive/releases/download/v3.8.7/libarchive-3.8.7.tar.gz`
  SHA-256 `4b787cca…b9166`; pinned fixed tarball
  `https://github.com/libarchive/libarchive/releases/download/v3.8.8/libarchive-3.8.8.tar.gz`
  SHA-256 `038918ea…306c190`.
- Fix commit `a20f89eb9b6eed62ee691b4d36fdf4e1216e0ba1` ("[Zip] Reject
  overlong pathnames in Zip writer", 2026-05-02),
  `https://github.com/libarchive/libarchive/commit/a20f89eb9b6eed62ee691b4d36fdf4e1216e0ba1.patch`,
  local SHA-256 `cb9a18bb…a49bad`. It is five added lines after
  `filename_length = path_length(zip->entry);`:
  `if (filename_length > 0xffff) { archive_set_error(&a->archive,
  ENAMETOOLONG, "Pathname too long for ZIP format"); return (ARCHIVE_FAILED); }`.

## Source-bound mechanism (read from pinned 3.8.7 bytes)

`libarchive/archive_write_set_format_zip.c` lines 289–320 define `cd_alloc()`:
a new `struct cd_segment` always gets `segment->buff_size = 64 * 1024` and
`segment->buff = malloc(segment->buff_size)` (L299–300), then returns the
current `p` and advances `p += length` unchecked (L317–318). In
`archive_write_zip_header()`, `filename_length = path_length(...)` at L961 is
stored as a 16-bit ZIP field at L1161/1187 but the *untruncated* length is
passed to `cd_alloc(zip, filename_length)` at L1191, and the returned pointer
goes straight to `copy_path()` at L1193. `copy_path()` computes
`pathlen = strlen(path)` at L2325 and performs `memcpy(p, path, pathlen)` at
L2328 with no capacity argument. Therefore bytes of the attacker-supplied
pathname at offsets 65536 and above are written verbatim past a 65,536-byte
malloc region; with a directory entry, L2332 adds one more unchecked byte.
The fix rejects the entry before `cd_alloc()`. Note the format constraint is
actually `0xffff`: a 65536-byte path is ASan-clean on the vulnerable build but
rejected by 3.8.8, so the lab's safe control uses 65535 bytes.

## Observed local reproduction (shipped CLI, GCC ASan)

`src/gen_tar.py` creates deterministic PAX-format tars with one entry whose
pathname is 65535 (`A`*65535), 65537 (`A`*65536 + `C` from the repeating
16-byte marker `CHOSEN-DEADBEEF!`) or 131072 bytes (64 KiB of `A` then marker
bytes at every offset ≥ 65536). The shipped CLI command is
`bsdtar --format=zip -cf OUT.zip @IN.tar` on both pinned builds.

- Vulnerable 3.8.7 + 65537 path: `AddressSanitizer: heap-buffer-overflow`,
  `WRITE of size 65537`, address `0 bytes after 65536-byte region`, frames
  `copy_path ...:2328` and `archive_write_zip_header ...:1193`; rc 1.
- Vulnerable 3.8.7 + 131072 path: same sink, `WRITE of size 131072`; rc 1.
- Vulnerable 3.8.7 + 65535 path: rc 0, no ASan report, non-empty ZIP.
- Official 3.8.8 on the two oversized paths: rc 0, no ASan report,
  `Pathname too long for ZIP format` on stderr and a 22-byte empty ZIP.
  The fix patch also applies cleanly to a copy of pinned 3.8.7 (source hash
  recorded in `PROVENANCE.md`).

No synthetic caller is involved: the sink and caller frames are in verbatim
pinned library code reached through the shipped binary. Traces are in the
lab's `evidence/`, inputs and outputs in `out/`, hashes and negatives in
`PROVENANCE.md`.

## Rung-4 feasibility and cheapest next experiment

The primitive is unusually friendly to rung 4: the write is a single `memcpy`
of verbatim, attacker-chosen bytes, its start offset and length are controlled
by the PAX pathname, and the source path is a shipped conversion CLI with no
authentication. What is *not* established is where those bytes land in a plain
build: under ASan they enter the redzone after a 65,536-byte region, which is
rung-3 corruption, not control of a live adjacent object. No pointer,
control-flow target, command or socket was exercised; the advisory's vector is
local with user interaction; rung 5 does not apply to this CLI path.

Cheapest next experiment: build pinned 3.8.7 without ASan, arrange the central
directory segment to be followed by a live heap object (groom with earlier
archive entries or a controlled allocator in a throwaway harness), then show
marker bytes at chosen offsets inside that object with a canary or debugger
readout; label the grooming conditions honestly. A loopback web/file-conversion
consumer that re-packs attacker archives would be the separate rung-5 path and
is not part of this stage.

## Duplicate and backlog check

No libarchive target mind or frontier brief exists; `rpm2shell` and
`synchronet2shell` use libarchive as a dependency for unrelated CVEs.
Three read-only advisory scouts were run this wake. Candidates preserved for
the next frontier wake (not staged here): PCRE2 JIT growable-stack underwrite
CVE-2026-103111 / GHSA-r9hj-j2rw-4q3m, fix `2b4038298072684b0fae29b15bedfb1a75bda46d`
(shipped `pcre2test` regression line; PCRE2 10.48 tarballs already provisioned
under `lab/frontier/pcre2jit2shell/`); GnuTLS DTLS fragment reassembly
CVE-2026-33846 / GNUTLS-SA-2026-04-29-1, fix `65ab33fa54e34fba69d793735b7df3d383d1ff78`;
libcoap Proxy-Uri CVE-2025-34468; biosig Intan CLP CVE-2026-22891; Suricata
Lua-OPT GHSA-8crg-r47r-h67c; MuPDF image stride CVE-2026-3308. Screened out as
duplicates: BZFlag (`bzfs2shell`), llama.cpp RPC (`llamarpc2shell`), Ruby/Perl
JSON bugs (owned lanes). Full scout reports are in the wake's agent artifacts,
not durable evidence; re-verify any candidate from primary sources before use.
