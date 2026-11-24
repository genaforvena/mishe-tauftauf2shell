# PROVENANCE — libraw2shell W197 (2026-11-24 04:56-05:0xZ)

All work is local provisioning plus lab execution. No external probe, no
scanner, no target beyond the pinned tarball and public PoC. No loopback
server was started; the consumer reads a local file.

1. Provisioned the pinned tarball, PoC zip and issue #894 text (read-only).
   Extracted PoC sha256 matches the issue exactly.
2. Built `pinned/LibRaw-0.22.3/bin/dcraw_emu` with gcc 14, `-O1 -g -DUSE_ZLIB
   -fsanitize=address -fno-omit-frame-pointer`, `-lz`. Real upstream consumer,
   not a harness stand-in.
3. Applied `pinned/fix-894.patch` to a copied tree and built the fixed ASan
   binary with identical flags. The first patch attempt failed because the
   hunk counts did not match the pinned context; the counts were corrected and
   the final hunk applies with fuzz 2 at line 74. Both attempts are preserved
   in git history and the patch file.
4. Built a genuinely plain `-O1` binary from a freshly extracted tarball
   (first attempt inherited copied ASan objects; `nm -D | grep -c __asan` was
   37 instead of 0, so it was discarded and rebuilt: 0 ASan symbols).
5. Built an `-O0` plain binary from a freshly extracted tarball for gdb locals.
6. Ran the three documented option forms (`-n 1`, `-C 1.1 1`, `-C 1 1.1`) on
   all three builds, plus the no-option safe control; captured ASan, RCs and
   gdb state into `evidence/`. `run-all.sh` now reproduces 10 PASS / 0 FAIL
   with log sha256 `8ad12e49ac28c2549b87c9707da47e632bcfbf99d5c7eb26716e950b9f874f57`.
7. Chosen-byte attempts (constant-value JPEG, black-level tag zeroing, full
   StripByteCounts, uncompressed constant pixels with relocated CFA) all
   failed to produce nonzero written values; they are preserved as negative
   results in `evidence/var-*.out`, `evidence/gdb-crafted-*.txt` and
   `craft_poc.py`. No chosen-byte claim is made.

 binaries are not committed (gitignored); `bootstrap.sh` rebuilds them from
the pinned tarball and patch. `evidence/evidence.log` carries the current
matrix and hashes.
