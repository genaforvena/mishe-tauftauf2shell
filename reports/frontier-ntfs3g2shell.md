# frontier-ntfs3g2shell — STAGED: shipped-CLI LZNT1 one-byte heap WRITE (CVE-2026-42618)

Status: **STAGED in W283 (2026-11-26); rung-3 ASan WRITE confirmed through the
shipped `ntfscat` CLI with a locally crafted 4 MiB NTFS image; rung 4 NOT
CLAIMED.** The W282 synthetic-caller observation below is retained as the
mechanism-first step. The W283 clean-archive runner
`lab/frontier/ntfs3g2shell/run-all.sh` reports PASS=31 FAIL=0: vulnerable
pinned build gives `WRITE of size 1` at verbatim `compress.c:568`, 0 bytes
after a 65,536-byte region, while the vendor-patched build and a safe stream
exit 0 ASan-clean. Charter, seed wall, status report and window are in place;
operator admission and witness replay are owed.

## Claim source and scope

- Vendor GHSA `https://github.com/tuxera/ntfs-3g/security/advisories/GHSA-6whp-3f63-97qw`
  (published 2026-07-15, High, CVSS 4.0 7.5 AV:L/AC:H): affected "2026.2.25
  and earlier", patched 2026.7.7. Claim: "a heap buffer overflow exists in
  `ntfs_decompress()` in compress.c that allows an attacker to corrupt one byte
  of heap memory in the SUID-root `ntfs-3g` binary by crafting a malicious NTFS
  image. The overflow is triggered by reading the special crafted file."
  Workaround: disallow compressed volumes. Credit Nozomi Labs NN-2026-0076.
- NVD (Analyzed), CPE `cpe:2.3:a:tuxera:ntfs-3g:*:*:*:*:*:*:*:*` with
  versionEndExcluding 2026.7.7, CVSS 3.1 7.1 AV:L AC:L PR:L C:N/I:H/A:H,
  CWE-122 + CWE-193. MITRE JSON
  `https://cveawg.mitre.org/api/cve/CVE-2026-42618` repeats the description
  but has `n/a` metadata; the vendor GHSA and patch are the authorities.
- Vulnerable tag `2026.2.25` (`libntfs-3g/compress.c`); fixed tag `2026.7.7`,
  release commit `d327833ec1d5eb1358b6f2c37139f10a3460944d`, tarball
  `https://tuxera.com/opensource/ntfs-3g_ntfsprogs-2026.7.7.tgz`, SHA-256
  `d67b769025d32860549d35c2147e45024d172f81c540d750390ce3602c059dab`.
  Fix commit `6aa66d98980ac1d966d7977c7b079f4fe380eb42` ("compress.c: Harden
  LZNT1 sub-block decompression bounds checks.", predecessor
  `e021cbe3d7a42963110e4561f2a1327614c20a00"), patch
  `https://github.com/tuxera/ntfs-3g/commit/6aa66d98980ac1d966d7977c7b079f4fe380eb42.patch`.

## Source-bound mechanism (read from pinned 2026.2.25 source)

`ntfs_decompress()` (`libntfs-3g/compress.c`) sets
`dest_end = dest + dest_size` and `dest_sb_end = dest + NTFS_SB_SIZE` (0x1000).
At L555 `if (cb > cb_sb_end || dest > dest_sb_end) goto return_overflow;`
and L566 `if (cb >= cb_sb_end || dest > dest_sb_end) break;` allow equality.
The symbol-token path at L569-575 executes `*dest++ = *cb++;` with no
`dest < dest_sb_end` guard. When the final 4 KiB sub-block is exactly full
and it is the last sub-block of the allocation, `dest_sb_end == dest_end`,
so the next symbol token writes one attacker-chosen byte one past
`ntfs_malloc(cb_size)` (plain malloc: ASan redzone exists). Phrase tokens
are length-checked and safe. Fix: on equality jump to `finish_compressed_sb`,
then `cb = cb_sb_end; goto do_next_sb;`, plus 2-byte header/truncation checks.

Shipped CLI path, no synthetic caller: `ntfsprogs/ntfscat.c` L343 uses a
4096-byte buffer, L370-377 loops over `ntfs_attr_pread()`; `libntfs-3g/attrib.c`
L1006-1009 dispatches compressed attributes to `ntfs_compressed_attr_pread()`,
which calls `ntfs_decompress()` at compress.c L956. `src/ntfs-3g.c` L1560
`ntfs_fuse_read()` L1620-1621 reaches the same function (the SUID binary named
in the advisory). `ntfscat` avoids FUSE dependencies.

## Local buildability check (observed, W282)

The pinned vulnerable tarball was provisioned into `/tmp/w282-ntfs` (tarball
SHA-256 `7754f3b32e8baf9c472459b4e9c981e3ae0f5039107cdd8d8201aed0a949008a`;
it extracts to `ntfs-3g-2026.2.25`). A full
`CFLAGS='-O1 -g -fsanitize=address -fno-omit-frame-pointer'
LDFLAGS='-fsanitize=address' ./configure --disable-shared && make -j6`
finished rc 0 and produced `ntfsprogs/ntfscat` (GCC ASan link flags in
`make-all.log`). No NTFS image was crafted and the CLI binary was not run on
an input, so this paragraph establishes buildability only. The separate
synthetic-caller result below supplies the ASan observation. `/tmp` artifacts
are outside the checkout and not committed.

## Observed synthetic-caller experiment (W282, ASan)

A throwaway harness under `/tmp/w282-ntfs` included the verbatim pinned
`compress.c` and called `ntfs_decompress(dest, 4096, cb, 2906)` directly. It
is NOT a shipped CLI call and NOT an NTFS image. Vulnerable tag: GCC ASan
`heap-buffer-overflow`, `WRITE of size 1`, verbatim `compress.c:568`, address
0 bytes after a 4096-byte malloc, rc 1 (`harness.out`). The upstream fix
commit patch failed 6 of 8 hunks on the 2026.2.25 tag; its partially patched
build still reported ASan at line 570, so the source copy was restored and
that failed control is preserved. The vendor-specific 2026.2.25 patch linked
from the GHSA applied cleanly: the same input gave rc 0 and no ASan report
(`harness-vendorfixed.out`). Rung-3 mechanics in the pinned function with a
synthetic consumer; do not relabel this as a CLI reproduction or rung 4.


## Observed shipped-CLI reproduction (W283)

`lab/frontier/ntfs3g2shell/` stages a clean-archive runner. Pinned `mkntfs`
bootstraps a deterministic 4 MiB image; `src/gen_image.py` patches MFT record 16
with a non-resident compressed `$DATA` (one cluster at LCN 1000, then a
15-cluster hole, compression unit 4) and puts the W282 stream in the 16th LZNT1
sub-block. The shipped `ntfscat -f -i 16 IMG` under GCC ASan gives
`heap-buffer-overflow`, `WRITE of size 1` at verbatim `compress.c:568`, 0 bytes
after a 65,536-byte region allocated at `compress.c:783`, through frames
`ntfscat.c:371 -> attrib.c:1003 -> compress.c:950`; 61,440 stdout bytes precede
the abort. The vendor-patched build emits 65,536 bytes with no ASan report; a
safe stream (two final literal tokens removed) is clean on both builds.
`sh run-all.sh` PASS=31 FAIL=0. Image and source hashes, control commands and
negatives are in the harness `PROVENANCE.md`; traces in `evidence/`.

## Rung-4 feasibility and cheapest experiment

One chosen byte at a fixed heap boundary supports rung 3 but not rung 4:
no arbitrary address, no pointer overwrite, no control-flow steering, and
no wire listener (rung 5 N/A). `AV:L` and a crafted-image precondition further
limit it. The advisory names the SUID `ntfs-3g` FUSE path; this lab cannot mount
(Operation not permitted), so only `ntfscat` was driven. If a plain-build
grooming experiment shows a chosen byte in an adjacent object, revisit;
until then do not infer a shell path.

Prior frontier notes (`reports/frontier-quickjsbcode2shell.md:99-100`,
`frontier-quickjsng2shell.md:104-106`) rejected this CVE as needing a
"wholesale decompressor rewrite"; the actual fix is ~102 changed lines of
bounds checks, so that rejection was overstated and is corrected here.
