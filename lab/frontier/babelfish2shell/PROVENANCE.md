# Provenance — Babelfish TDS prelogin extracted harness

All external material below was fetched read-only for provisioning on
2026-11-20. No probe, connection or traffic was sent to any non-loopback
system; no Babelfish/PostgreSQL server was started.

## Advisory / claim sources

- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-119923 (CNA Amazon,
  published 2026-11-06, updated 2026-11-07): heap-based buffer overflow in the
  TDS prelogin parser, Babelfish extension 1.0-1.5/2.1-2.15/3.1-3.12/
  4.0-4.8/5.1-5.4 and Amazon Aurora PostgreSQL with Babelfish; remote
  unauthenticated crafted TDS prelogin packet to the TDS port (default 1433);
  CWE-122; CVSS 3.1 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, CVSS 4.0 9.3.
  Record also consolidates a NULL-pointer-dereference finding.
- GHSA: https://github.com/babelfish-for-postgresql/babelfish_extensions/security/advisories/GHSA-vq28-vgj3-r26w
  (Critical 9.8, published 2026-11-07 by shardgupta).
- AWS bulletin: https://aws.amazon.com/security/security-bulletins/2026-166-aws/
  (2026-166-AWS, 2026-11-06). Describes CVE-2026-119923 as unauthenticated
  connection-handshake memory corruption and CVE-2026-119924 (authenticated
  RPC procedure-name OOB read) as a separate issue.
- Mirrors read for cross-check:
  https://github.com/advisories/GHSA-g64g-7679-7c73 and
  https://osv.dev/vulnerability/CVE-2026-119923 .
  OSV's GIT range endpoints (86c24eb5..., a2ab3b3d...) are CI-only commits in
  the packaging repo, not the code fix; they are NOT used as fix evidence.

## Fix identification

Fix commit found by listing commits touching
`contrib/babelfishpg_tds/src/backend/tds/tdslogin.c` at tag BABEL_4_10_0:

- `ab820bddaffa540af82f2f689c3e535f82f14d89`, "[OSS-ONLY] Minor fixes and
  improvements in TDS and PL/tsql handling (#4955)", 2026-08-26.
  https://github.com/babelfish-for-postgresql/babelfish_extensions/commit/ab820bddaffa540af82f2f689c3e535f82f14d89
  Its `tdslogin.c` hunk adds the `length > TDS_DEFAULT_INIT_PACKET_SIZE`
  rejection, `enlargeStringInfo` before `TdsGetbytes`, the no-options check,
  the ENCRYPTION-length check and the login offset/bound checks.
  The same fix is present at BABEL_5_6_0 (`66fe10002e37`) and BABEL_6_1_0
  (`f0b8bd54aad1`) under different backport SHAs.

## Fetched files (raw.githubusercontent.com, read-only)

| File in this dir | Upstream URL | SHA-256 |
| --- | --- | --- |
| `tdslogin.c.BABEL_4_8_0` | https://raw.githubusercontent.com/babelfish-for-postgresql/babelfish_extensions/BABEL_4_8_0/contrib/babelfishpg_tds/src/backend/tds/tdslogin.c | `eff24f8e517d73eb6025a93602cd5e1910ae8fb59d3d6c0f3980dd96686961f9` |
| `tdslogin.c.BABEL_4_10_0` | https://raw.githubusercontent.com/babelfish-for-postgresql/babelfish_extensions/BABEL_4_10_0/contrib/babelfishpg_tds/src/backend/tds/tdslogin.c | `364f362968e3b03e9de8456c6985ba76ea3a4e2169e53c09beb518be3e677346` |
| `tdscomm.c.BABEL_4_8_0` | https://raw.githubusercontent.com/babelfish-for-postgresql/babelfish_extensions/BABEL_4_8_0/contrib/babelfishpg_tds/src/backend/tds/tdscomm.c | `dd6db9f7f0a088a023fd5f92c4dd7c430b8770496826a8d46d82fecb5092d36c` |
| `tds_int.h.BABEL_4_8_0` | https://raw.githubusercontent.com/babelfish-for-postgresql/babelfish_extensions/BABEL_4_8_0/contrib/babelfishpg_tds/src/include/tds_int.h | `33b513d13375257186b93e1d19a50d01491e5b003dbe6834422b326c759ec705` |
| `stringinfo.c.REL_16_STABLE` | https://raw.githubusercontent.com/postgres/postgres/REL_16_STABLE/src/common/stringinfo.c | `b8affb64791ecebf788d8cd9403fe0481ac92a5f324518b653b75c76b3cbd557` |
| `fix-ab820bdd.patch` | https://github.com/babelfish-for-postgresql/babelfish_extensions/commit/ab820bddaffa540af82f2f689c3e535f82f14d89.patch | `fd3fba26a31f4b651d7c7cd179c6c72a7e0e7e165f34f7446ad5de458c543f56` |

Key source facts (line numbers from the exact files above):

- `tdslogin.c.BABEL_4_8_0:193-200` — `PreLoginOption` has a `uint16_t length`
  and an inline `StringInfoData val`.
- `tdslogin.c.BABEL_4_8_0:357-363` — offset and length read as network-order
  16-bit values, followed by `initStringInfo(&temp->val)`. No bounds check.
- `tdslogin.c.BABEL_4_8_0:377-383` —
  `TdsGetbytes(prev->val.data, prev->length)` for each option; `val.data` is
  still the 1024-byte initial allocation.
- `tdscomm.c.BABEL_4_8_0:634-659` — `TdsGetbytes` copies `min(LeftInPacket,
  len)` bytes with `memcpy` in a loop until `len` is exhausted.
- `tds_int.h.BABEL_4_8_0:50` — `#define TDS_DEFAULT_INIT_PACKET_SIZE 4096`.
- `stringinfo.c.REL_16_STABLE` `initStringInfo`: `int size = 1024;
  str->data = palloc(size); str->maxlen = size;`.
- `fix-ab820bdd.patch` tdslogin.c hunk: rejects `length > 4096`, then
  `resetStringInfo`, `enlargeStringInfo(&prev->val, prev->length)`, copy,
  `val.len = length`, NUL terminate.
