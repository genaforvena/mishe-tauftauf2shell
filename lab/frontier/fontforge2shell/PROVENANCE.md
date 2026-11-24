# PROVENANCE — fontforge2shell W196

All external reads were provisioning on 2026-11-24 04:33-04:34Z:
- VulnCheck advisory page for CVE-2026-135295 (claim, versions, CVSS,
  references).
- `https://raw.githubusercontent.com/fontforge/fontforge/20251009/fontforge/fvimportbdf.c`
  (2530 lines, sha256 `df766f9c…81f0eb30d`), stored under `pinned/`.
- `https://github.com/fontforge/fontforge/commit/65e80b5dfb6691a1c8a532cfbb8ec905949e0c9a.patch`
  (23 lines, sha256 `f2745243…5e99175`), stored under `pinned/`.
- GitHub commit API for the fix parent hash `c83ff048…e692218` and stats
  (1 file, +1/-1).

No probe, scan or client run touched any external host. All builds and
runs are local, with an in-memory `fmemopen()` table; no loopback service
was needed. `harness.c` copies the pinned function and PCF helpers verbatim,
with `figureProperEncoding()` stubbed and minimal struct stand-ins; the
`FIXED` branch is the verbatim fix line. `run-all.sh` rebuilds five
binaries, runs the attack and two controls, probes chosen bytes with gdb,
and writes `evidence.log` with per-file sha256s.

An author-side clean `git archive e5e4a65` replay is recorded in
`REPLAY.md`: 5/5 expected RCs and normalized hash `56fd8ada…5633bb`.
Independent witness replay (message #3309, clean archive of `13a2a94`,
gcc 13.3.0 / gdb 15.1) confirmed the same matrix and bytes and graded
rungs 1-4 ESTABLISHED at the direct-call scope, NO r5.

W2 (2026-11-24 07:4xZ): no new external reads. The vulnerable source
tarball and pinned patch provisioned in W1 were reused; the extra plain
Debug builds (`build-plain/`, `build-fixed-plain/`) and all gdb runs were
local and loopback-free. The only new input file is the already-pinned
`truncated.pcf` driven through the real headless scripting `Import()`.
W2 transcripts and their sha256s are recorded in `REACHABILITY.md`.

W3 (2026-11-24 08:0xZ): no external reads or new source trees. The same
plain Debug builds, pinned input files and `gdb` were used locally to
inspect the malloc chunk header before/after the negative write and at
`free(encs)`; see `CONSUMER.md` and the transcript sha256s there. No
loopback service, GUI or external target was involved. This extension is
author-side and awaits any independent witness verdict.

W4 (2026-11-24 10:3xZ): no external reads or new source trees. Four new
PCF inputs were derived locally from the already-pinned `truncated.pcf`
by truncating at byte 0x122 and appending one glyph-index low byte; the
same local ASan/plain/fixed builds and gdb were used. `STEERING.md` has
input hashes, transcripts and the failed first byte placement. No loopback
service, GUI or external target was involved; this extension is author-side
and unwitnessed, with no grade change.

W5 (2026-11-24 14:0xZ): no external reads or new source trees. Four new
PCF inputs were derived locally from the already-pinned `truncated.pcf`
by rewriting the BDF_ENCODINGS min/max fields and truncating at byte
0x123; `make-size-case.py` records the byte offsets and derivation. The
same local ASan/plain/fixed builds and gdb were used; `SIZE.md` holds the
input hashes, transcripts, return codes and the negative tcache-consumer
probe. No loopback service, GUI or external target was involved. A GUI
build was not attempted because `gtk+-3.0` is not installed here. This
extension is author-side and unwitnessed, with no grade change.

W6 (2026-11-24 19:2xZ): no external reads or new source trees. W5's
pinned `size-91.pcf` was reused; `sponge-32.pcf` was generated locally
from the pinned `truncated.pcf` PROPERTIES table plus a minimal 32-glyph
METRICS/BITMAPS/ENCODINGS set (`make-consumer-case.py` records the byte
layout). The same local plain, patched and ASan builds and gdb were
used; `CONSUME.md` holds the input/transcript hashes, return codes, the
real gettext consumer and the preserved negative lanes. The overflow
bytes come from this host's locale path, not from any external source;
no probe, scan or client contacted any external host and no loopback
service was involved. This extension is author-side and unwitnessed,
with no grade change.

W7 (2026-11-24 20:0xZ): no external reads or new source trees. All PCF
inputs were derived locally from the already-pinned `truncated.pcf`;
`make-filechoice-case.py` records the byte offsets, including the one-byte
`props[2].name_offset` variant. The same local plain, patched and ASan
builds and gdb were used; `FILECHOICE.md` holds input, command, transcript
and output hashes, the file-chosen byte comparison, return codes and the
two superseded size-class attempts. No loopback service, GUI or external
target was involved. This extension is author-side and unwitnessed, with
no grade change.

W8 (2026-11-24 21:0xZ): no external reads, no new source and no new PCF
bytes. Reused the pinned `truncated.pcf` / `complete.pcf` and the same
local plain, patched and ASan builds. The two scripts (`open-path.ff`,
`open-complete.ff`) and gdb command files are local text; all transcripts
are in `OPENPATH.md` with input, command and output hashes. `fontforge
truncated.pcf` without a script was also run locally as a negative lane;
no loopback service, GUI or external target was involved. Author-side and
unwitnessed, with no grade change.

