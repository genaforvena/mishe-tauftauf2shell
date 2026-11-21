# Provenance — dnsmasq2shell frontier harness (2026-11-21)

All fetching was read-only provisioning from public sources; no probe was
sent off loopback and no dnsmasq daemon was built or run.

## Claim sources

- CVE-2026-12725 / GHSA-hv63-qc47-8j8h, published 2026-06-22. Ubuntu record
  <https://ubuntu.com/security/CVE-2026-12725> (read 05:44Z): priority Medium,
  CVSS 5.9 `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H`; fixed in Ubuntu
  `2.92-1ubuntu0.4` (26.04), `2.90-2ubuntu0.4` (24.04),
  `2.90-0ubuntu0.22.04.4` (22.04); upstream patch named as commit `36d081e`.
- Red Hat BZ 2490763 (XML view, read 05:44Z):
  <https://bugzilla.redhat.com/show_bug.cgi?id=2490763&ctype=xml>. Its first
  comment states a 46-byte `daemon->addrbuff`, a trigger DS with
  keytag=65535/algo=255/digest=255, a bounded ~12-byte overflow, and that
  the bytes are not attacker-controlled; it names the same upstream fix
  commit and calls the fixed release "dnsmasq 2.92rel2".
- Upstream fix patch (read 05:44Z):
  <https://github.com/imp/dnsmasq/commit/36d081e37477027fd721fea498f3760f529034ad.patch>.
  Commit author Simon Kelley, date 2026-04-21T21:14:41Z, subject
  "Fix buffer overlow in log_query()". Changes `src/cache.c` and `src/dnssec.c`.

## Exact pins and fetch method

Fetched with `curl -fsSL` from `raw.githubusercontent.com/imp/dnsmasq/<ref>/src/<file>`
into `lab/frontier/dnsmasq2shell/pins/`, sha256 verified by `run.sh`:

| ref | file | sha256 |
| --- | --- | --- |
| tag `v2.92` (tag object `70c72407fe4a12018f5f00922ca2dc3f6e37b856`) | `cache.c` | `2918f3929b7054caa657c927ad98c2daa0aed5bf981990a6494c53d90d6e7f30` |
| tag `v2.92` | `dnssec.c` | `bf7f09dd004fd98d4bc46fbc965fb7a10bd28d06b096e7a60101ead4da19879f` |
| tag `v2.92` | `dnsmasq.h` | `1c277ee55d326fcaf220dc1723ea7576c49a88555b7c1eef97d7c6936270afb9` |
| fix commit `36d081e37477027fd721fea498f3760f529034ad` | `cache.c` | `2833788d0cd52df0b4d2e0c3374ff9b7933811735cbff6a37ff010b1735bcece` |
| fix commit `36d081e37477027fd721fea498f3760f529034ad` | `dnssec.c` | `c69256bf3c2405db4595d51d92e3e84eb5ccbd539847177209b0d96a3f7d9c74` |

`ADDRSTRLEN` is `INET6_ADDRSTRLEN` (46) per pinned `dnsmasq.h:171`; flag bit
values used by the stubs come from the same header (lines 523-538).

## Conflict preserved, not resolved

The GitHub API lists the fix commit's first parent as
`8741128120f41cfc0a1fbf6d3e11f94e821f418a`, but raw fetch of that SHA returned
404 and the commits API returned 422 — the parent is not reachable in this
mirror, so no A/B against the exact fix parent is available. More importantly,
at fetch time the mirror's `master` and tags `v2.92` / `v2.92test22` **still
contain the vulnerable `sprintf`** at the same site, so `36d081e` is not on the
mirrored master branch; "fixed version" is a distribution backport, not an
upstream release tag. This is recorded as a claim conflict, not a fix.

## Harness boundary

`run.sh` extracts verbatim `cache.c:2266-2291` (v2.92) and `cache.c:2333-2364`
(fix commit) under `#line "cache.c"` directives; `driver.c` supplies stub
`querystr`, `sanitise`, `option_bool`, a synthetic `union all_addr`, and a
heap `addrbuff`. The DS format strings are checked to be verbatim
`dnssec.c:1100` (vulnerable) and `dnssec.c:1101` (fixed). Capture mode places
an instrumented victim immediately after byte 46 of one arena; ASan mode uses
a separate exact-size heap allocation so ASan redzones detect the write.
No dnsmasq process, network, DNS packet, parser, resolver, DNSSEC validation,
logging configuration, socket or pointer arithmetic is used. Rung 4 cannot be
claimed: the overflow bytes are a fixed literal from the caller, not chosen
by an attacker.
