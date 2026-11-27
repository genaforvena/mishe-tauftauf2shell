# libvorbislap2shell — provenance (W376, 2026-11-27)

## Claim pins

- CVE-2026-137079, CNA MITRE record published 2026-11-25:
  https://cveawg.mitre.org/api/cve/CVE-2026-137079
  Claim: libvorbis through 1.3.7, `_ov_getlap()` in `lib/vorbisfile.c` passes
  a negative sample count from `vorbis_synthesis_lapout()` to `memcpy()`;
  a short valid Ogg Vorbis file with suitable block sizes and two lapped
  seeks can overwrite stack frames in a decoder application.
- Upstream references recorded in the CVE: v1.3.7 source at
  https://github.com/xiph/vorbis/blob/v1.3.7/lib/vorbisfile.c#L2242,
  https://github.com/xiph/vorbis/blob/v1.3.7/lib/block.c#L1034,
  proposed fixes https://github.com/xiph/vorbis/pull/136 and
  https://github.com/xiph/vorbis/pull/139. Both PRs were **open and unmerged**
  when read on 2026-11-27; there is no released fixed version. The 2.1.x
  numbering in other advisories does not apply here.
- Provisioning is read-only fetching of public sources and patches. No Ogg
  file is generated and no application, listener or external host is contacted.

## Source pins (SHA-256, verified on every run by `src/SHA256SUMS`)

- `src/vorbis-v1.3.7.tar.gz` from
  https://github.com/xiph/vorbis/archive/refs/tags/v1.3.7.tar.gz:
  `270c76933d0934e42c5ee0a54a36280e2d87af1de3cc3e584806357e237afd13`.
- `src/pr136.diff` from https://github.com/xiph/vorbis/pull/136.diff:
  `39041eac50979acb2efcc7e3b9afe0e899e449e21c33834c7b2117ee4e55744e`.
  It changes `samples==0` to `samples<=0` and the zero-fill size to
  `sizeof(**pcm)*(lapsize-lapcount)`; it is the effective fixed control for
  this harness.
- `src/pr139.diff` from https://github.com/xiph/vorbis/pull/139.diff:
  `414622fd531bf69336216213dd7a967a5e8ef68d2b51c4dddcfe6b8cd3f9bcb1`.
  It fixes the root cause in `vorbis_synthesis_lapout()`; pinned here but not
  used by the synthetic driver, whose stand-in returns a caller-chosen count.

## Harness boundary

`harness/gen.sh` extracts the tail of the pinned `_ov_getlap()` from
`lib/vorbisfile.c` verbatim (lines 2238-2253 of the v1.3.7 tarball, located
by the comment `failed to get lapping data`) under `#line` directives.
Only the surrounding types and `vorbis_synthesis_lapout()` are stand-ins;
the pinned body's `if`, both `for` loops, `memset`, both `memcpy` calls and
`lapcount` updates are the fetched bytes. `run-all.sh` builds vulnerable and
PR136-patched arms with GCC 13.3.0 at `-O0 -g`, both under ASan and with
`-fno-stack-protector`, then runs sample counts `-4` and `0`. Raw logs with
PIDs/addresses are gitignored; the 16 assertions in `run-all.sh` are the
stable, path-independent checks.
