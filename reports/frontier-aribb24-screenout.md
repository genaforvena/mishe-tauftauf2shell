# frontier brief — aribb24 (CVE-2026-112280), SCREENED OUT

Status 2026-11-25 07:10Z: no stage, no window. Read-only advisory review only;
no source fetch, build or probe.

## Verified ground truth

- CVE-2026-112280 / GHSA-pgf4-9h53-rfcj, published 2026-10-19 by VulnCheck,
  GitHub advisory unreviewed, moderate 6.9,
  CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:H. CWE-122 heap-based
  buffer overflow in `src/parser.c` of libaribb24 <= 1.0.3, function
  `parse_data_unit_statement_body`; oversized caption data unit supplied in a
  crafted caption PES packet via `arib_parse_pes()`. Sources:
  https://github.com/advisories/GHSA-pgf4-9h53-rfcj ,
  https://www.cve.org/CVERecord?id=CVE-2026-112280 ,
  https://www.vulncheck.com/advisories/libaribb24-aribb24-through-1.0.3-heap-buffer-overflow-via-parse-data-unit-statement-body .
- Advisory lists affected versions as "unknown" and patched versions as
  "unknown"; no fix commit, PR or tag is named. It reports crash and possible
  further heap corruption, not a demonstrated pointer or control-flow write.

## Mechanism available from the claim

Pass-1/pass-2 style overflow while parsing a data-unit statement body in the
caption PES parser (source-bound only to `src/parser.c`, function named in the
advisory). No pinned bytes were read: the reference points at the v1.0.3 tree
but no patch hunk exists to compare against.

## Feasibility and disposition

SCREENED OUT this wake: the advisory is old (2026-10-19), AV:L with passive
UI, moderate severity, names no fix commit or patched release, and the claimed
primitive is "crash + possible corruption" without a write-what-where.
Ranking by tractability puts the freshly observed dr_wav 0.14.5 write-what-
where (with an upstream 0.14.6 bound-check control) ahead of it. A later wake
may provision v1.0.3, pin `parse_data_unit_statement_body()` and test whether
a length word drives a heap write; until then rung status is UNKNOWN.

Also screened: fontforge issue #5951 (`cvar` parser out-of-bounds write) is a
duplicate of the already-owned `fontforge2shell` lane; MediaInfoLib 11/23
entries are read-only UAF/OOB reads and that project was previously screened
for build cost; GHSA CWE-filtered 11/25 entries were Tenda/Webmin noise. No
new target staged from these.
