# Provenance — Perl2Shell frontier candidate (CVE-2026-15534)

Created 2026-11-21 ~20:45Z by `frontier`. Provisioning only: public advisory
and upstream source reads; no build, no local service, no traffic, no probes
off loopback.

## Claim sources (fetched read-only)

- CPAN Security Group CVE record: `https://cveawg.mitre.org/api/cve/CVE-2026-15534`
  (published 2026-08-09, updated 2026-09-08). Gives affected range through
  5.45.1, both fix commit URLs, the 286331153-byte / 15-node arithmetic, and
  CWE-190/125/787.
- oss-security disclosure: `http://www.openwall.com/lists/oss-security/2026/08/09/12`,
  Stig Palmquist, 2026-08-09 19:51:48 +0200. Read verbatim; restates the CVE.
- Secondary, not relied on for bytes: NVD CVE detail, GHSA-2cxw-qmfc-3vx3,
  Ubuntu USN-8736-1, Debian security tracker.

## Pinned source bytes

`src/SHA256SUMS` lists seven files, all fetched from upstream URLs below and
verified `sha256sum -c SHA256SUMS` 7/7 OK at 2026-11-21 20:45Z. GitHub raw tag
files and auto-generated commit patches have no published digests, so these are
self-computed fingerprints of the exact bytes read; re-fetch and compare before
relying on them.

| File | URL |
| --- | --- |
| `src/v5.45.1-regexec.c` | `https://raw.githubusercontent.com/Perl/perl5/v5.45.1/regexec.c` |
| `src/v5.45.2-regexec.c` | `https://raw.githubusercontent.com/Perl/perl5/v5.45.2/regexec.c` |
| `src/v5.44.0-regexec.c` | `https://raw.githubusercontent.com/Perl/perl5/v5.44.0/regexec.c` |
| `src/v5.45.1-regexp.h` | `https://raw.githubusercontent.com/Perl/perl5/v5.45.1/regexp.h` |
| `src/v5.45.2-regexp.h` | `https://raw.githubusercontent.com/Perl/perl5/v5.45.2/regexp.h` |
| `src/568e6fd.patch` | `https://github.com/Perl/perl5/commit/568e6fd238867bb9e99fa3f47cba3169009239e0.patch` |
| `src/54cf3d4.patch` | `https://github.com/Perl/perl5/commit/54cf3d44cbbedd17d774e9a37921963e8fd5d0cb.patch` |

(The table has seven rows; `SHA256SUMS` has seven entries — all seven verified.)

## Key raw observations

- `v5.45.1-regexec.c:9200-9206`: signed `I32` multiply, negative-only clamp.
- `v5.45.2-regexec.c:9243-9254`: `STRLEN` `len`, overflow guard, cache disabled
  when the product would overflow.
- `v5.45.1-regexec.c:9235-9248`: OOB read index from real match position ×
  node count, stored into `ST.cache_offset` / `ST.cache_mask`.
- `v5.45.1-regexec.c:6504-6507`, `:9287`, `:9297`, `:9321`: `CACHEsayNO`
  single-bit OR write at `ST.cache_offset`.
- `v5.44.0-regexec.c:9136-9142` and `v5.44.0/regexp.h:833-834`: same vulnerable
  `I32` code in a released stable tag (source observation only).

Rung 0 throughout. No trigger, no ASan report, no bytes, no witness claim.
