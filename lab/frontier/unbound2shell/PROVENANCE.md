# Provenance — unbound2shell frontier harness (2026-11-21)

All fetching was read-only provisioning from public sources; no probe was
sent off loopback and no Unbound process, resolver or packet was created.

## Claim sources

- CVE-2026-81642, CNA NLnet Labs, read 06:2xZ:
  <https://cveawg.mitre.org/api/cve/CVE-2026-81642>. Description: "A DNSKEY
  with an owner compression pointer to its own RDATA can overflow the digest
  buffer. Remote code execution is possible through attacker controlled
  data." CNA CVSS 4.0 9.1 Critical; NVD CVSS 3.1 9.8, CWE-122.
- Upstream advisory <https://nlnetlabs.nl/downloads/unbound/CVE-2026-81642.txt>
  and index <https://nlnetlabs.nl/projects/unbound/security-advisories/>:
  "denial of service and possible remote code execution as a result of
  digesting DNSKEYs"; "An adversary can exploit the vulnerability by
  controlling a malicious zone and querying a vulnerable Unbound."
  Severity Critical; fixed in 1.26.1 by a capacity check after decompression.
- GHSA mirror <https://github.com/advisories/GHSA-xxc4-rpp8-3fw7> (versions
  listed Unknown), NVD <https://nvd.nist.gov/vuln/detail/cve-2026-81642>.
- Fix commit <https://github.com/NLnetLabs/unbound/commit/8c2e0fd6cc5b>
  (`ds_create_dnskey_digest` in `validator/val_sigcrypt.c`, +2/-0) and fixed
  release <https://github.com/NLnetLabs/unbound/releases/tag/release-1.26.1>.
- Config-gate question: UNKNOWN. No authoritative page states whether DNSSEC
  validation must be enabled; the second-hand observation that NLnet Labs
  attaches no config condition is not used as fact.

## Exact pins and fetch method

Fetched with `curl -fsSL` from
`https://raw.githubusercontent.com/NLnetLabs/unbound/<ref>/<path>` into
`lab/frontier/unbound2shell/pins/`. `run.sh` verifies these sha256 values on
every replay.

| ref | file | sha256 |
| --- | --- | --- |
| `release-1.26.0` | `validator/val_sigcrypt.c` → `val_sigcrypt.1260.c` | `477d5e1b6ebdc829a7dd0bcb660f3e26123381fe6d4b7df401c5a17b4611f954` |
| `8c2e0fd6cc5b` | `validator/val_sigcrypt.c` → `val_sigcrypt.fixcommit.c` | `a490e4bc4525706f573dab8d2ccd0d58f6301ab530f2dd7fc2720be318bdcb6f` |
| `release-1.26.1` | `validator/val_sigcrypt.c` → `val_sigcrypt.1261.c` | `807b97e8a4684266324a6e387280e0408141e566e406b23e0f68f11670bd4dc4` |
| `release-1.26.0` | `sldns/sbuffer.h` → `sbuffer.h` | `06c463e9ddd4ad106de0b895cb575936a11242f7ea3fce3df943c9cbdd70e7a5` |
| `release-1.26.0` | `sldns/sbuffer.c` → `sbuffer.c` | `eace1c553e69e95b976448860b89f42ddc1dd84a682e3ac42f4fdf7ee3d65303` |
| `release-1.26.0` | `util/config_file.c` → `config_file.c` | `393cc9fd020651d546e7cf5085ef64faad92a2fc9f485f99c43b203cfa395cb3` |
| `release-1.26.0` | `daemon/worker.c` → `worker.c` | `37afa74d86317dbe961943b118afc95273361e5d4e5c3be5e7ddb0d7435f90a9` |
| `release-1.26.0` | `sldns/rrdef.h` → `rrdef.h` | `2bddf6e3c4a337a3a0481a9f9b732b2e478d5f01311fdb3e7d7663560c982570` |
| `release-1.26.0` | `validator/val_secalgo.c` → `val_secalgo.c` | `2ae7b032cc1d73005b5fe40bebf60363f09d402cc4bacb7c5313f6cdcdeb1acc` |

All three claimed refs returned HTTP 200. The fix-commit post-image
`val_sigcrypt.c` is 1769 lines, the 1.26.0 pin 1767; the 1.26.1 pin is 1867
lines and adds `MAX_VALIDATE_NSECS`, so the whole files are NOT byte-identical
— only the two guard lines and the function body match. The 1.26.0 pin has
no `sldns_buffer_available` guard in `ds_create_dnskey_digest`; both fixed
pins do.

Key pinned lines asserted by `run.sh`: `val_sigcrypt.1260.c:294` (function
name), `:307` (clear), `:308` (dname write), `:311` (RDATA write),
`val_sigcrypt.fixcommit.c:308` and `val_sigcrypt.1261.c:310` (guard),
`config_file.c:176` (`msg_buffer_size = 65552`), `worker.c:2436` (scratch
buffer), `rrdef.h:29` (`LDNS_MAX_DOMAINLEN 255`), `rrdef.h:249`
(`LDNS_MAX_RDFLEN 65535`), `sbuffer.h:436` (`memcpy`), `sbuffer.c:19`
(`sldns_buffer_new`).

## Harness boundary

`run.sh` extracts verbatim `validator/val_sigcrypt.c:293-317` (vulnerable),
`:293-319` (fix commit) and `:295-321` (fixed tag) under `#line` directives.
`stubs.h` reproduces the pinned `sldns_buffer_new` body
(`sldns/sbuffer.c:19-42`) and the pinned buffer primitives
(`sldns/sbuffer.h:189`, `206`, `270`, `343`, `411`, `423`, `433`, `462`) with
`#line` attribution; the `sldns_buffer_write_at` memcpy is verbatim except
for the `assert()` at `sldns/sbuffer.h:435` that `NDEBUG` removes. The harness
compiles with `NDEBUG`; shipping release flags are UNKNOWN. `driver.c`
supplies stub `rrset_get_rdata`, `query_dname_tolower`, `ds_get_digest_algo`
and `secalgo_ds_digest`, and sets the attacker-controlled name/RDATA lengths
to the pinned wire maxima. It uses a static stdio buffer so the non-ASan run
can observe bytes after the 65552-byte allocation without a post-overflow
`malloc` (glibc otherwise aborts on corrupted top-chunk metadata).

No Unbound daemon, socket, DNS packet, wire parser, decompression,
DNSSEC validation, real allocator adjacency, control-flow diversion, pointer
overwrite or marker execution is exercised. Rung 4 is INSTRUMENTED only:
attacker-pattern bytes are observed past the synthetic heap allocation in the
lab frame; shipping heap layout, allocator behavior, canary, ASLR and NX are
UNKNOWN.

Trace hashes exclude ASan PID, address and build-path text so replays are
byte-identical across directories.
