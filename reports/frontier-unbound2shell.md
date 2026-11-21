# frontier-unbound2shell — Unbound DNSKEY DS-digest heap overflow (CVE-2026-81642)

## Claim (not yet observation)

CVE-2026-81642, CNA NLnet Labs. CWE-122 heap buffer overflow. CNA CVSS 4.0
9.1 Critical `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/U:Red`;
NVD CVSS 3.1 9.8 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (Ubuntu
priority Medium — vendor variance, kept as claim). Affected: all versions
through `1.26.0` (CNA range 0 to <1.26.1; OSV tags `release-0.0` through
`release-1.26.0`). Fixed: `1.26.1`. Upstream fix commit
`8c2e0fd6cc5b6eaa618ac72227808824b4edee7c` (short ref `8c2e0fd6cc5b`
verified; full hash from the claim source).

Claim sources (read-only provisioning, no probing):
- CVE record <https://cveawg.mitre.org/api/cve/CVE-2026-81642>:
  "A DNSKEY with an owner compression pointer to its own RDATA can overflow
  the digest buffer. Remote code execution is possible through attacker
  controlled data."
- Upstream advisory <https://nlnetlabs.nl/downloads/unbound/CVE-2026-81642.txt>:
  "denial of service and possible remote code execution as a result of
  digesting DNSKEYs"; "An adversary can exploit the vulnerability by
  controlling a malicious zone and querying a vulnerable Unbound."
- Advisory index <https://nlnetlabs.nl/projects/unbound/security-advisories/>:
  "Severity: Critical"; fix "properly check the offending buffer's capacity
  after decompression and before writing."
- GHSA mirror <https://github.com/advisories/GHSA-xxc4-rpp8-3fw7>,
  NVD <https://nvd.nist.gov/vuln/detail/cve-2026-81642>,
  fix <https://github.com/NLnetLabs/unbound/commit/8c2e0fd6cc5b>,
  fixed release <https://github.com/NLnetLabs/unbound/releases/tag/release-1.26.1>.

Config gates: UNKNOWN. No authoritative source states whether DNSSEC
validation must be enabled. Attacker preconditions per the maintainer: control
a malicious zone and get a vulnerable Unbound to query it; CVSS says
unauthenticated remote with no user interaction. The compression-pointer
inflation narrative above is claim until reproduced — the local harness uses
pinned maximum lengths directly, not a DNS wire parser.

## Source-bound mechanism

Affected pin: tag `release-1.26.0`, `validator/val_sigcrypt.c:293-317`
(`ds_create_dnskey_digest`), reached from `ds_digest_match_dnskey()` at
`:325-367` during DS/DNSKEY validation:

```c
sldns_buffer_clear(b);
sldns_buffer_write(b, dnskey_rrset->rk.dname,
	dnskey_rrset->rk.dname_len);
query_dname_tolower(sldns_buffer_begin(b));
sldns_buffer_write(b, dnskey_rdata+2, dnskey_len-2); /* skip rdatalen*/
sldns_buffer_flip(b);
```

`b` is `env->scratch_buffer`, a single per-worker heap allocation
`sldns_buffer_new(cfg->msg_buffer_size)` at pinned `daemon/worker.c:2436` with
default `cfg->msg_buffer_size = 65552` at pinned `util/config_file.c:176`.
Both writes are `memcpy` at pinned `sldns/sbuffer.h:436`; its only capacity
check is `assert()`, absent under `NDEBUG`, which a shipping build defines.
The name and RDATA lengths are bounded separately by the wire format —
`LDNS_MAX_DOMAINLEN 255` (`sldns/rrdef.h:29`) and
`LDNS_MAX_RDFLEN 65535` (`sldns/rrdef.h:249`) — but their sum is not bounded
against the scratch buffer: `255 + (65535-2) = 65788`, 236 bytes past 65552.

Upstream fix commit `8c2e0fd6cc5b` inserts, at
`validator/val_sigcrypt.c:308-309`:

```c
if(!sldns_buffer_available(b, dnskey_rrset->rk.dname_len + dnskey_len-2))
	return 0; /* buffer too small */
```

The same two lines are present at tag `release-1.26.1`
`validator/val_sigcrypt.c:310-311`. The two files are **not** byte-identical
overall (1769 vs 1867 lines; 1.26.1 also adds `MAX_VALIDATE_NSECS` NSEC
limiting); only the guard and function body match. This was verified, not
assumed.

## Pins and local harness

Nine pins under `lab/frontier/unbound2shell/pins/`, fetched verbatim from
`raw.githubusercontent.com/NLnetLabs/unbound/<ref>/<path>`, sha256-listed in
`lab/frontier/unbound2shell/PROVENANCE.md` and re-verified by `run.sh` on
every replay. `run.sh` extracts the verbatim function block —
`val_sigcrypt.c:293-317` (vulnerable), `:293-319` (fix commit),
`:295-321` (fixed tag) — under `#line` directives, and asserts the exact
pinned buffer, constant and `memcpy` lines. `driver.c` supplies stub
collaborators: a heap `sldns_buffer` whose `sldns_buffer_new` and write path
are the pinned bodies compiled under `NDEBUG`; no resolver, DNS packet,
parser, socket or network.

The non-ASan vulnerable run uses a static stdio buffer (`setvbuf`) because the
236-byte overwrite corrupts glibc's top-chunk metadata and the next `malloc`
aborts before the bytes can be observed. This is a measurement choice for the
lab frame, not a claim about a shipping build's allocator behavior.

## Evidence ladder (observed 2026-11-21 06:31Z)

Working-tree replay `bash lab/frontier/unbound2shell/run.sh <outdir>`:
**29 PASS / 0 FAIL, `ALL CHECKS PASSED rc 0`**, trace
`sha256=05bf4ace988fc4fdc4d213674e1f30e85c739c170b47c5319cbfc2cd7f24f795`.
Two clean `git archive HEAD` (`f9295a0`) extractions were replayed into
absolute directories `replay-1` and `replay-2` with the unmodified `run.sh`:
both returned 29 PASS / 0 FAIL and `ALL CHECKS PASSED rc 0`, with byte-identical
`trace.txt` sha256 `05bf4ace988fc4fdc4d213674e1f30e85c739c170b47c5319cbfc2cd7f24f795`.

- Rung 1 — deterministic trigger: pinned max lengths `dname_len=255`,
  `rdata_len=65535` yield `written=65788`, `overflow=236`, `rc=1`;
  a benign case (`32`/`100`) yields `written=130`, `overflow=0`.
- Rung 2 — accounting failure: the vulnerable build returns success
  (`rc=1` from the digest stub) with no guard (`GUARD_REJECTED=0`) although
  `limit=65788 > cap=65552`; both fixed builds return 0 and set
  `GUARD_REJECTED=1` on the same input, while still accepting the benign case.
- Rung 3 — ASan confirms corruption: `heap-buffer-overflow`, `WRITE of size
  65533`, `sldns/sbuffer.h:436` (pinned `memcpy`), called from
  `val_sigcrypt.c:311` (pinned second write), 0 bytes after the 65552-byte
  region allocated at `sldns/sbuffer.c:27`. Nonzero ASan rc.
- Rung 4 — INSTRUMENTED only: 16 bytes at `data+65552` in the non-ASan lab
  frame equal the attacker-chosen RDATA pattern (`CHOSEN_MATCH=1`,
  `44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 41 42 43`). No pointer, saved
  return address, control-flow diversion or benign marker execution was
  observed or attempted.

## Feasibility and cheapest next rung

Tractability: high for rungs 1-3 on pinned source; the fix is a two-line
capacity check, the lengths are pinned wire maxima, and the overflow is a
plain `memcpy`. UNKNOWN for a real receiver: no stock Unbound process, DNSKEY
wire bytes, decompression path, DNSSEC configuration, allocator layout or
shipping compile flags were exercised. The advisory's compression-pointer
route to an inflated owner name is not reproduced here; the harness supplies
a 255-byte `dname` directly.

Cheapest next rung: build stock `release-1.26.0` under ASan with DNSSEC
validation enabled, bind only 127.0.0.1, serve a local malicious zone whose
DNSKEY owner name uses a self-referential compression pointer, and query it
from the lab resolver; capture the real ASan frame, wire bytes and post-write
heap state. Repeat with `release-1.26.1` as control. If chosen RDATA bytes
land in an adjacent heap object or pointer, attempt a benign marker before
claiming rung 4; otherwise keep the INSTRUMENTED label.

Every claim in the first section remains a claim: this brief reproduces the
pinned code path and its memory effect, not advisory reachability or
severity.
