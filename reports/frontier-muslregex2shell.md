# frontier-muslregex2shell — musl `regcomp()` int overflow (CVE-2026-107891)

Status: **SCREENED, NOT STAGED (W271 2026-11-26)**. Verified pins and patch,
but the named overflow input did not produce a bounded ASan observation on
this host; both pinned builds ran past a 90-second wall-clock timeout in the
standalone harness. Preserved as a negative, not retried into existence.

## Verified ground truth (claims and pins)

- CVE-2026-107891, maintainer advisory on oss-security
  https://seclists.org/oss-sec/2026/q4/289 (2026-10-21), CVSS 3.1 8.1 AV:N.
  Patch attachment
  https://seclists.org/oss-sec/2026/q4/att-289/0001-regex-avoid-int-overflow-in-regcomp.patch
  was fetched and read: 35 insertions, 6 deletions in `src/regex/regcomp.c`.
- Vulnerable pin v1.2.6 `9fa28ece75d8a2191de7c5bb53bed224c5947417`, verified
  from https://git.musl-libc.org/cgit/musl/tag/?h=v1.2.6 . Fix commit
  `7813e9119eb5fe681b6750b8a033a0490bca0941` (parent
  `f607123b7210b52ddfff7c8d5a8a9b84efbe2d6b`), verified from
  https://git.musl-libc.org/cgit/musl/commit/?id=7813e9119eb5fe681b6750b8a033a0490bca0941 .
  `git ls-remote` could not be used: the musl server redirects the git smart
  HTTP endpoint to cgit, so cgit refs are the pin source here.
- Patch mechanism: an upfront `strnlen(regex, 1024000)` input limit, a
  `check_add()` helper guarding six `int` additions, and `xmalloc` ->
  `xcalloc` for `counts`/`offs`. The commit names
  `(((a{255}){255}){255}){255}` as the position-overflow input.

## Bounded attempt and negative result

- Snapshots fetched from cgit (sha256 `e9db8b70…` for 1.2.6 and `8c16adf9…`
  for the fix). A lab-only compatibility `regex.h` reproduced musl's
  `regex_t` layout so the verbatim `regcomp.c` and `tre-mem.c` compiled against
  the host libc with GCC ASan; build-only defines were `-Dhidden=`,
  `-DCHARCLASS_NAME_MAX=14`, `-DRE_DUP_MAX=255` (upstream `limits.h` values).
  Both pinned trees compiled cleanly.
- A driver called the pinned public `regcomp(&re, pat, REG_EXTENDED)` with the
  upstream-named 27-character pattern. Under `timeout 90`, **both** the
  vulnerable and fixed builds produced only the initial `MODE=attack`
  line and were killed at rc 124; no ASan report, no return value, no
  fixed-control rejection was observed in the budget. The unfixed tree may be
  expanding an enormous repetition tree before the overflow, or the standalone
  libc shim may be too slow; cause UNKNOWN.
- No harness claim, no rung, no window, no admission. The local harness and
  logs remain in `lab/frontier/muslregex2shell/` (gitignored).

## Cheapest next experiment if revived

Build musl's own `libc.a` with the pinned trees and use musl's own allocator
under a bounded memory limit, or instrument `tre_expand_ast()` to count the
expanded positions before allocation. Derive the shortest repetition shape
that overflows `position` without expanding 255^4 states first. Keep the
fixed build's `REG_ESPACE` rejection as the control; do not infer a rung from
this timed-out attempt.
