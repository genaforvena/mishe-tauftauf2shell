# frontier-dnsmasq2shell — dnsmasq `log_query()` DS/DNSKEY logging heap overflow

## Claim (not yet observation)

CVE-2026-12725 / GHSA-hv63-qc47-8j8h, published 2026-06-22. Ubuntu records
Medium 5.9, `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H` (availability only);
Red Hat BZ 2490763 likewise describes a denial-of-service impact. The claim:
with DNSSEC validation **and** query logging enabled, logging a DS or DNSKEY
reply with an unsupported algorithm or digest type overflows an internal
logging buffer. Red Hat's bug text specifies a 46-byte `daemon->addrbuff`, a
trigger DS with keytag 65535 / algorithm 255 / digest 255, and a bounded ~12
byte overflow whose bytes are *not* attacker-controlled; maintainer Simon
Kelley is quoted as saying this is not a likely RCE vector. GHSA lists no
package and "unknown" affected/fixed versions; there is no package-level
version range to trust. Vendor/advisory prose here is a claim, not evidence.

Sources: <https://ubuntu.com/security/CVE-2026-12725>,
<https://bugzilla.redhat.com/show_bug.cgi?id=2490763>,
<https://github.com/advisories/GHSA-hv63-qc47-8j8h>,
<https://github.com/imp/dnsmasq/commit/36d081e37477027fd721fea498f3760f529034ad.patch>.

## Source-bound mechanism

Affected pin: tag `v2.92` (`70c72407fe4a12018f5f00922ca2dc3f6e37b856`),
`src/cache.c:2291`:

```c
else if (flags & F_KEYTAG)
  sprintf(daemon->addrbuff, arg, addr->log.keytag, addr->log.algo, addr->log.digest);
```

`daemon->addrbuff` has `ADDRSTRLEN` = 46 bytes (`dnsmasq.h:171`). The caller
at `src/dnssec.c:1100` passes a *format string that already contains the
literal* `" (not supported)"`:

```c
log_query(F_NOEXTRA | F_KEYTAG | F_UPSTREAM, name, &a,
          "DS for keytag %hu, algo %hu, digest %hu (not supported)", 0);
```

With maximum-width numeric fields the formatted result is 57 bytes plus NUL
into a 46-byte buffer — 12 bytes past the end. The upstream fix commit
`36d081e37477027fd721fea498f3760f529034ad` (2026-04-21) removes the suffix
from the two callers, passes `!algo_digest_name(algo)` instead of a literal 0,
moves the suffix into `log_query()`'s separate `extra` pointer, changes
`sprintf` to `snprintf(daemon->addrbuff, ADDRSTRLEN, ...)`, and adds
`F_KEYTAG | F_RR` to the earlier `querystr()` guard so a type string cannot be
substituted for the format. The patch's single removed `F_KEYTAG` `sprintf`
is at parent line 2358 — the same site as v2.92:2291; the fixed
`src/cache.c:2358-2362` is the new `snprintf`/`extra` block, not a second path.

**Claim conflict preserved:** the fix commit's first parent
`8741128120f41cfc0a1fbf6d3e11f94e821f418a` is not reachable in the GitHub
mirror (raw 404, API 422), and the mirror's `master` plus tags `v2.92` and
`v2.92test22` still carry the vulnerable `sprintf` at fetch time. "Fixed in
2.92rel2" (Red Hat) and Ubuntu's backported package versions are distribution
facts, not an upstream release tag containing this commit. No fixed *release
tag* pin exists for this candidate.

## Pins and local harness

Exact file hashes and fetch URLs are in
`lab/frontier/dnsmasq2shell/PROVENANCE.md`; the four fetched source pins live
under `lab/frontier/dnsmasq2shell/pins/` and are re-verified by `run.sh` on
every replay. `run.sh` extracts verbatim pinned `cache.c:2266-2291` and
`cache.c:2333-2364` under `#line "cache.c"` directives; `driver.c` supplies
stubbed collaborators, checks the DS format strings against verbatim pinned
`dnssec.c` lines, and compiles a vulnerable capture build, an ASan build and
a fixed-control build. No dnsmasq process, DNS packet, network, socket,
resolver or DNSSEC validation is used.

## Evidence ladder (observed 2026-11-21 ~05:55Z)

Working-tree replay of `bash lab/frontier/dnsmasq2shell/run.sh <outdir>`:
**22 PASS / 0 FAIL, `ALL CHECKS PASSED rc 0`**, trace
`sha256=2673af32ec5fb1de34bf7774184551cd727e18abd00b80b733122d232c630e42`
(canonical lines only; ASan PID/address/path text excluded). A clean
`git archive HEAD` replay at commit `25ca75d`, run twice into separate
absolute output directories from the extracted tree, gave 22 PASS /
`ALL CHECKS PASSED rc 0` both times with the same trace sha256 (byte-identical
between directories).

- **Rung 1 (reproducible trigger)** — `LAYOUT buflen=46 written=57
  overflow=12 keytag=65535 algo=255 digest=255 type=0`: the verbatim
  `sprintf` writes 58 bytes including NUL into a 46-byte heap object.
- **Rung 2 (observed state failure)** — `VICTIM first_changed=0
  tail=20737570`: the bytes immediately past the buffer change from their
  pre-call sentinel value.
- **Rung 3 (ASan-confirmed heap corruption)** — `heap-buffer-overflow`,
  `WRITE of size 58`, frame `cache.c:2291` (`sprintf`) from an exact-size
  46-byte heap allocation.
- **Rung 4 (INSTRUMENTED only)** — the overflow bytes are the deterministic
  literal tail of `" (not supported)"` (`20 73 75 70` = `" sup"` at offsets
  46-49) and are read back byte-exact from the instrumented adjacent region.
  There is **no attacker-chosen byte, no pointer control and no execution**;
  the fixed control writes 41 bytes, leaves the victim untouched and moves the
  suffix into `extra`. Rung 4 is not achievable through this overflow path as
  documented: the bytes are caller literals, not attacker data.

## Feasibility and cheapest next experiment

Ranking: **LOW tractability for rung 4**, despite a network-facing daemon and
a PR:N advisory vector. The primitive is a bounded, literal-bytes heap
overflow, and reaching it needs both DNSSEC validation and query logging plus
a malicious upstream DS/DNSKEY reply (matching the advisory's AC:H). A live
full-daemon ASan build would upgrade the *observation* (rung 3 in the real
process) but cannot turn fixed suffix bytes into control.

Cheapest experiment that would move this up a rung: build the unpatched
`v2.92` tree with `--dnssec --log-queries`, run it bound to 127.0.0.1 only,
point its forwarder at a loopback authoritative responder serving a DS with
keytag 65535 / algorithm 255 / digest 255, and record the ASan report and
crash under that real config; then repeat with the patched distro package or
a tree carrying commit `36d081e` as the control. Do not contact external
resolvers or authoritative servers.

## Disposition

Frontier brief only; no local full-daemon build this wake, and no admission
requested. This candidate is recorded to keep the bounded-overflow class
distinct from the length-controlled overflows already admitted. Any future
target mind must first resolve the missing upstream fixed-release pin and the
unreachable fix parent before spending lab time on rung 4.

## Handoff

Both required artifacts for a find are live: this brief and a registered
two-pane `dnsmasq2shell` window (inner socket, window index 33; top shows the
brief, bottom runs `plant_view --role dnsmasq2shell --output --log --follow`),
with seed wall `.mishe-tauftauf/walls/dnsmasq2shell.md` and an entry in
`operator/window-registry.json`. The operator owns admission; no charter,
route entry or wake unit is claimed by frontier. Given the literal-bytes
primitive and missing fixed-release pin, admission is not requested.
