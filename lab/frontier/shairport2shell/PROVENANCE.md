# Provenance — shairport2shell frontier harness

## Claim source (read-only provisioning, no external probing)

- Maintainer security advisory GHSA-6g79-wrcj-h8xw, "RTSP unrecognised-method
  hex-dump stack buffer overflow (pre-authentication)", published 2026-09-04,
  `https://github.com/mikebrady/shairport-sync/security/advisories/GHSA-6g79-wrcj-h8xw`.
  High 7.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, CWE-121,
  "No known CVE". The advisory states AirPlay-2 builds before 5.5 are affected;
  patched versions 5.5 and 5.6-dev. This is a claim, not a reproduction.
- Upstream fix PR #2263 (development):
  `https://api.github.com/repos/mikebrady/shairport-sync/pulls/2263`, merged
  2026-08-26 into `development`, merge commit
  `74d59d8f83538c03852d51f953a2ca7716340fc2`.
- Master backport PR #2267:
  `https://api.github.com/repos/mikebrady/shairport-sync/pulls/2267`, merged
  2026-08-31 into `master`, merge commit
  `a5d8f46a54c0440bdd5290d385fe8a740c636d36`.

## Pinned upstream bytes

Raw-file fetches, all from `https://raw.githubusercontent.com/mikebrady/shairport-sync/<ref>/rtsp.c`:

| role | ref | full SHA | rtsp.c sha256 |
| --- | --- | --- | --- |
| affected | `a50f18469143b9dbe599b8333d228a586dc29e67` (parent of fix commit `c1c41c4`) | `c1c41c4ec9937eb7d2f8819dadd5bc45f65ab3f4` | `7cc04130d403a16474e6541726062e4352d6fe0fe532555362d77205a9ba8883` |
| fixed | `c1c41c4ec9937eb7d2f8819dadd5bc45f65ab3f4` | — | `69b23114c7e90433a9bb49378444646e5b03b39ecc79bec5c5e254d34a35fea3` |

Commit metadata was read from
`https://api.github.com/repos/mikebrady/shairport-sync/commits/<sha>`: `c1c41c4`
has one parent `a50f184`, touches only `rtsp.c`, and its message is the
buffer-size fix. Tag `5.5` (`663499543b53`) carries the fixed declaration at
`rtsp.c:4260`; tags `5.2.3` and `5.4-dev` carry the small declaration. The
harness pins the commit pair rather than tags so affected and fixed bytes differ
only by this patch.

## Harness construction

`run.sh` checks the two pinned sha256 values, asserts the exact upstream lines
and their line numbers (`rtsp.c:4208` buffer declaration, `:4215` two-hex-chars
per byte), then extracts **lines 4206–4221 verbatim** from each pinned file into
`gen_block.h` under a `#line 4206 "rtsp.c"` directive. `driver.c` includes that
generated header; the vulnerable declaration, clamp, hex loop and trailing
`debug()` are the upstream statements themselves, not a reimplementation.

Only the surrounding scaffolding is harness-authored: a `req` object holding
`contentlength`/`content`, a no-op-ish `debug` macro that captures the real
`obf[]` pointer, and a 512-byte `victim` stack array declared immediately before
the block so the overflow past `obf[4096]` can be observed. The victim snapshot
is copied inline before any further call because a later `printf` frame can
reuse the dead callee stack. Rung 4 stays **INSTRUMENTED**: chosen bytes are the
hex encoding of a token-safe alphabet read back at requested offsets in that
harness object; no live daemon, no socket, no pointer control, no execution.

ASan is compiled from the same generated header with
`-fsanitize=address -fno-omit-frame-pointer`; the reported frame points at the
real pinned line `rtsp.c:4215`. Trace hashing normalises ASan addresses and
paths so replays are byte-identical.
