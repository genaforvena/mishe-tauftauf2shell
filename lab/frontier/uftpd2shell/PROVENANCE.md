# Provenance — uftpd2shell frontier harness

All fetches were read-only provisioning over HTTPS on 2026-11-21. No probe
was sent to any system; nothing ran off-loopback.

## Authoritative claim sources

- cvelistV5: `https://cveawg.mitre.org/api/cve/CVE-2026-59964`
- Maintainer security advisory: `https://github.com/troglobit/uftpd/security/advisories/GHSA-vqhc-mmjf-972h`
- CVE title: "uftpd: Stack-based buffer overflow in compose_path() via overlong
  FTP path". CNA GitHub_M, published 2026-11-18T20:26:33Z, updated
  2026-11-19T14:58:51Z. CWE-121. CVSS 3.1 5.9 MEDIUM
  `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H`.
- Affected `< 2.16`, fixed `2.16` (release
  `https://github.com/troglobit/uftpd/releases/tag/v2.16`).
- CISA ADP SSVC: Exploitation `poc`, Automatable `no`, Technical Impact
  `partial`.
- The GitHub advisory API endpoint `api.github.com/advisories/GHSA-vqhc-mmjf-972h`
  returned HTTP 404 at fetch time; the cvelistV5 record and the advisory web
  page are the sources actually read.

## Fix commit

- `f5552a8c6a5f14691f51bef1f3373747259d7ac8`, "Bound path length when
  composing non-chroot paths", Joachim Wiberg, 2026-06-21T10:31:28+0200.
- Patch: `https://github.com/troglobit/uftpd/commit/f5552a8c6a5f14691f51bef1f3373747259d7ac8.patch`
- It adds exactly 11 lines to `src/common.c` immediately before the `memmove`,
  bounding `len` and NUL-terminating `dir` so `strlen(dir) + len + 1 <=
  sizeof(dir)`.

## Pinned bytes (sha256, verified by run.sh on every replay)

| file | sha256 | source URL |
|---|---|---|
| `src/common.c.v2.15` | `9efddcbc1ee9309961b71d30e241f0c0d7d8b67a8b15123fdd006f82c9f22aff` | `https://raw.githubusercontent.com/troglobit/uftpd/v2.15/src/common.c` |
| `src/common.c.v2.16` | `2d63f3f9fdec49bba897c07d2799dfdaf65c9ead4ba2fd5358d49cde8426ee56` | `https://raw.githubusercontent.com/troglobit/uftpd/v2.16/src/common.c` |
| `src/fix.patch` | `1427fdce2eadd378716546c45fede1f76c62657780385e923bb1ef6446f545d7` | fix-commit `.patch` URL above |

Pinned call sites: vulnerable `memmove(dir + len, ...)` at
`common.c.v2.15:61`, `memcpy(dir, home, len)` at `:62`; fixed guard at
`common.c.v2.16:66-70`, `memmove` at `:72`.

## Harness honesty

`run.sh` extracts the **verbatim** `compose_path()` body from each pinned file
at replay time (from its signature through its closing brace) and pads leading
blank lines so ASan line numbers equal the upstream file's line numbers. The
function is never reimplemented. `uftpd.h` is a minimal local stand-in for the
upstream header: it supplies `ctrl_t` (with the real `cwd[PATH_MAX]` field),
the `home`/`chrooted` globals and no-op debug macros. Everything that matters
to the overflow — the stack `dir[PATH_MAX]`, the `strlcat` cap, the `memmove`
and the fix guard — comes from the pinned source bytes.

`driver.c` sets `chrooted = 0` (advisory's non-chroot precondition), a 128-byte
configured `home`, `cwd = "/"`, and a 4095-byte client path whose tail carries
the chosen marker and chosen 64-bit value. The advisory's default `/srv/ftp`
home case (9-byte overflow) was NOT exercised; that magnitude is UNKNOWN here.

No live uftpd process, no stock build, no allocator-layout claim and no
return-address or function-pointer control is claimed.
