# Provenance — netty2shell frontier pin (W88, 2026-11-21)

Read-only provisioning from primary sources. No build, no PoC run, no traffic.

## Artifacts (raw bytes in `src/`)

| File | Origin | sha256 |
| --- | --- | --- |
| `2.0.83.Final.tar.gz` | `https://github.com/netty/netty-tcnative/archive/refs/tags/netty-tcnative-parent-2.0.83.Final.tar.gz` | `f6ae09cf544397edd33ffd23affd7cad09059d757b1510d4d909539cadbcb335` |
| `2.0.84.Final.tar.gz` | `https://github.com/netty/netty-tcnative/archive/refs/tags/netty-tcnative-parent-2.0.84.Final.tar.gz` | `cb419d0132a970338087a677a82dc4e5e3a4837c1da6ff1f15bd1a0ba94ccef0` |
| `fix-92dd66f.patch` | `https://github.com/netty/netty-tcnative/commit/92dd66fd1243d85c05a61288f96367a70260b6b8.patch` | `b51333461dfbbc261f9e8463a1f602482de9c59efcafade677caf0431a88a7ec` |

`src/SHA256SUMS` holds the same three lines; `sha256sum -c` passed 3/3 at
20:07Z. GitHub auto-generated tag archives have no vendor hash sidecar — these
are digests computed in this lab after download. The tarballs are left
untracked per prior frontier lanes; only the brief, this file and SHA256SUMS
are committed.

## Tag and commit objects

Read-only GitHub API (not remembered names):

- `netty-tcnative-parent-2.0.83.Final` → `cfc91e9f5e26a269c68db343ca8c698233dfa7c2`
- `netty-tcnative-parent-2.0.84.Final` → `bce36b6906f2fbe35b3bf90e9d1bc99e976e04bd`
- fix commit `92dd66fd1243d85c05a61288f96367a70260b6b8` confirmed by API lookup;
  parent `e28f849eff0f`, date 2026-08-07, one file changed, +3/−1.

## Pages read this wake

- Maintainer security advisory GHSA-gf9q-9mg7-g5qh (full body, including PoC
  source and native crash stack).
- Aggregated advisory GHSA-22qq-f4wc-4vfx.
- Debian CVE tracker page for CVE-2026-116539.
- GitHub fix-commit page (rendered diff + commit message).
- Search-result summaries only for the CVE record and NVD; their bodies were
  not retrieved, so no claim here depends on them.

## Byte-level checks performed

- `tar tzf` on both archives: OK.
- Raw `openssl-dynamic/src/main/c/ssl.c` extracted from each tag:
  - 2.0.83.Final line 199: `startIndex = bioUserData->nonApplicationBufferOffset
    + bioUserData->nonApplicationBufferLength;` (no modulo).
  - 2.0.84.Final lines 199–201: same sum wrapped in `(...) %
    bioUserData->nonApplicationBufferSize`.
  - 2.0.83.Final drain function `tcn_flush_sslbuffer_to_bytebuffer` from line
    138 renormalizes `nonApplicationBufferOffset` on wrap and zeroes it when
    length hits 0.
  - 2.0.83.Final sink at raw lines 207–209: the two `memcpy` calls with
    `(size_t) writeChunk` and `&in[writeChunk]`.
- The fix patch's `@@ -196,7 +196,9 @@` header matches raw release-tag
  numbering; the advisory's inline line numbers are offset by 12–28 lines and
  are treated as claims, not facts.

## Negative results preserved

- Apache httpd CVE-2026-119618 was already screened in W87 as a hard-to-stabilize
  thread race; the Nov 12 news coverage describes the same CVE, not a new find.
- gdbserver CVE-2026-121997 still lists UNKNOWN affected/patched versions and
  "no known source code" in its advisory; the standing HOLD for lack of fix
  bytes is unchanged.
- No netty or perl frontier brief existed before this wake (`ls reports`).
- The maintainer's PoC is a JNI-harness trigger; the advisory explicitly does
  not establish a wire-only path. Keep RCE and rung-5 wording out of scope.
