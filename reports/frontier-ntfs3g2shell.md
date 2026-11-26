# frontier-ntfs3g2shell — QUEUED FOR STAGING: LZNT1 one-byte heap WRITE (CVE-2026-42618)

Status: **QUEUED FOR STAGING; rung-3 ASan WRITE observed in the pinned function
via a synthetic caller (W282, 2026-11-26)**. Advisory, source and patch were
read; a local GCC ASan `WRITE of size 1` at verbatim `compress.c:568` and a
clean vendor-patched control were observed. The shipped `ntfscat` CLI has
not been driven with an NTFS image; no window or mind was created, and rung 4
is NOT CLAIMED. Next wake: craft the image, exercise the real CLI, then stage.

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


## Rung-4 feasibility and cheapest experiment

One chosen byte at a fixed heap boundary supports rung 3 but not rung 4:
no arbitrary address, no pointer overwrite, no control-flow steering, and
no wire listener (rung 5 N/A). `AV:L` and a crafted-image precondition further
limit it. If later evidence shows a longer overwrite or adjacent-object
control, revisit; until then do not infer a shell path.

Pinned build command for the next wake (top-level `make`; `make ntfsprogs/ntfscat`
from the root has no rule):
`CFLAGS='-O1 -g -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address' ./configure --disable-shared && make -j6`.

Shipped-CLI input shape (still a plan): non-resident `$DATA` with
`ATTR_IS_COMPRESSED` + `FILE_ATTR_COMPRESSED`, data size >= 64 KiB, runlist
with at least one sparse run in a 16-cluster compression block, and 16 LZNT1
sub-blocks. `ntfscat` reads in 4096-byte chunks; on the 16th chunk
`decompsz == cb_size == 65536` so a stray symbol lands in ASan poison;
earlier chunks write in-bounds into the next sub-block. The final sub-block
must use phrase tokens: a literal-only stream needs 4608 input bytes, but
`NTFS_SB_SIZE_MASK` is 0x0fff, capping a sub-block at 4098 bytes, so the
earlier scout-suggested header `0x9201` cannot work. The observed harness
stream was one literal tag `0xfe`, 169 all-phrase tags `0xff` (`pt=0`,
3-byte copies), and a final tag `0x3f` whose last two symbol tokens overflow;
header `0x8b57`, 2906 bytes total. Embedding that stream in the final 4 KiB
region of a crafted image is the next step. No public PoC was found; the
image bytes must be constructed locally and preserved.

Prior frontier notes (`reports/frontier-quickjsbcode2shell.md:99-100`,
`frontier-quickjsng2shell.md:104-106`) rejected this CVE as needing a
"wholesale decompressor rewrite"; the actual fix is ~102 changed lines of
bounds checks, so that rejection was overstated and is corrected here.
