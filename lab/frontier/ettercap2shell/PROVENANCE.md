# Provenance — ettercap2shell frontier candidate

CVE-2026-125401 / GHSA-vrjv-f8gv-2h35, ettercap Gadu-Gadu dissector
`gg_get_version()` heap write. Everything here is read-only provisioning from
public sources plus local direct-call experiments; no probe contacted anything
outside the plant's own network namespace and no loopback service was used.

## Claim sources (read 2026-11-23)

- `https://github.com/Ettercap/ettercap/security/advisories/GHSA-vrjv-f8gv-2h35`
  — GitHub CNA advisory, published 2026-11-06. Exact words: "`gg_get_version()`
  ... composes a version string with `sprintf`/`strcat` into a 30-byte heap
  buffer, and can produce up to 44 bytes"; vulnerable `<= 0.8.4.1`, patched
  `0.8.5.1`; `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` (8.1 HIGH),
  CWE-131 + CWE-787. The advisory quotes caller line 357
  `SAFE_CALLOC(tbuf3, 30, sizeof(char));`, helper lines 616–695, the
  `version=0x44000042` 43-byte string plus NUL = 44 bytes, and an ASan
  `WRITE of size 13` trace. It also claims "partially attacker-selected"
  overflow bytes — see the correction below.
- `https://api.osv.dev/v1/vulns/CVE-2026-125401` — CVE published
  2026-11-09T23:28Z by VulnCheck, aliases GHSA-vrjv-f8gv-2h35, CVSS v4
  `AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H`, CWE-122 in the CVE record,
  fixed commits `832524f3...` and `1d8badb713579419a29a494bb463a1af59707e98`,
  fixed version 0.8.5.1. Note the competing CWE/GHSA-CVE scores are a claim
  discrepancy, not a merged fact.
- `https://github.com/Ettercap/ettercap/pull/1330` — PR closed, opened
  2026-09-08, release announcement for 0.8.5 then 0.8.5.1 in comments on
  2026-11-10. Covers seven DREAM-team findings; only the gg one was used here.

## Pinned bytes

Fetched with `curl -fsSL` from `raw.githubusercontent.com` on 2026-11-23.
`src/SHA256SUMS` is authoritative for these hashes.

| File | Source | SHA-256 (first 12) | Role |
|---|---|---|---|
| `src/ec_gg.c.3548c10` | commit `3548c10c30c730e92035f793a1b6ff31e028acc8` | `1369e5c88fec` | vulnerable helper, lines 616–695 |
| `src/ec_gg.c.v0.8.4.1` | tag `v0.8.4.1` | `a97a0984f9c9` | released vulnerable blob |
| `src/ec_gg.c.a8c1a50` | PR #1330 branch head `a8c1a5085791b38c234be0e4129302fdc36964e0` | `a516ce050828` | fixed helper, lines 631–717 |
| `src/ec_gg.c.1d8badb7` | merged fix commit `1d8badb713579419a29a494bb463a1af59707e98` | `a516ce050828` | byte-identical to the PR blob |
| `src/ec_gg.c.v0.8.5.1` | tag `v0.8.5.1` | `a516ce050828` | byte-identical to the merged fix |
| `src/fix-pr1330.patch` | PR #1330 patch as staged by an earlier wake | `4ab380d9fa46` | fix hunk, two `snprintf(str, size, ...)` sites |

Applicability check (local): the 80-line `gg_get_version()` body at
`v0.8.4.1:599-678` hashes `9c04673eeae4...`, identical to the body at
`3548c10:616-695`. The fixed file from PR head, merged commit and release tag
all hash `a516ce050828...`. So the extracted vulnerable helper is the shipped
0.8.4.1 code and the extracted fixed helper is the shipped 0.8.5.1 code, not a
synthetic stand-in.

## Harness

`harness/driver.c` includes the helper source re-extracted verbatim on every
run by `harness/run.sh` (`#line` marker plus exact line ranges; SHA-256
asserted for driver, both pinned files, both release blobs, fix patch and both
extracted slices). `u_int32` is the ettercap typedef, declared locally.
Modes: `arith` (independent length arithmetic), `plain` (128-byte workspace
with canary, exact OOB bytes), `asan` (caller-sized allocation with ASan
redzone starting at the allocation end). Compiles with gcc and clang ASan;
fixed variant is compiled with `-DFIXED_VARIANT`.

No ettercap build, no dissector loop, no listener, no network. The harness
models the caller's 30-byte heap allocation; it does not reproduce the
surrounding Gadu-Gadu packet parsing or the real heap layout.

Replay: 53 PASS / 0 FAIL three times plus one clean `/tmp` copy; normalized
trace hash `d650b34e3bbc1ea336c60d2cb4b9c7743fdc4657b7d8e0d07c7e1bc1c1027b7a`.
Raw outputs are in `harness/evidence/`; `normalized.txt` removes PID,
addresses, source paths and frame numbers.

## Rung ladder and limits

- Rung 1: independent arithmetic for `0x44000042` gives 43 chars + NUL in a
  30-byte object = 14-byte overflow, matching the helper's actual 43 chars.
  Note `%X` prints 1–8 digits: `0x04000042` has seven digits, so its base
  string is 19 chars, not 20. The driver models that exactly; an earlier
  wrong assumption was corrected rather than kept.
- Rung 2: plain run gives `STR_LEN=43`, `OOB_COUNT=14`, write stops at NUL
  with canary `0xee` after it.
- Rung 3: gcc and clang ASan `heap-buffer-overflow`, `WRITE of size 13`,
  `0 bytes after 30-byte region`, frame `gg_get_version`. This is the
  advisory's trace shape reproduced on locally pinned bytes.
- Rung 4 (scoped, partial): the input bits select whether the overflow occurs
  and how many bytes cross the boundary. With both flags the exact OOB tail is
  `69 6f 20 2b 20 65 72 61 6f 6d 6e 69 78 00` (`io + eraomnix\0`); with
  `0x44000018` only the terminating NUL crosses; with `0x04000042` likewise.
  Chosen hex digits `44` or `5a` land byte-exact at offsets 11..18 but stay
  INSIDE the 30-byte allocation. Correction to the advisory: the OOB bytes
  are fixed suffix literals chosen by input bits, not arbitrary attacker
  bytes; no arbitrary-byte write, no pointer control, no marker, no RCE.
- Controls: fixed helper truncates to 29 chars in a 30-byte object, writes
  the full 43 in a 64-byte object, and is ASan-clean in both; vulnerable
  helper with safe version `0x2a` writes 3 chars and is ASan-clean.

## Live experiment (done 2026-11-23, ettercap2shell wake 02:57Z)

The cheapest next experiment was completed on the same day. Real ettercap
`v0.8.4.1` (HEAD `0dc8409`, `ec_gg.c` hash `a97a0984...` — the same bytes as
the pinned blob above) and `v0.8.5.1` (HEAD `832524f3`, `a516ce05...`) were
built with clang ASan. A crafted `GG_LOGIN50_CMD` packet with
`version=0x44000042` reaches `gg_get_version()` from `dissector_gg:360`
**before** the length guard at `ec_gg.c:361`, both in offline pcap replay and
as a live frame injected on loopback. ASan reports `WRITE of size 13`,
`0 bytes after 30-byte region`, allocation `dissector_gg:356`; extent controls
give `WRITE of size 12` at line 676. Safe version, wrong type, server-side
direction and the fixed build are all clean. See
`reports/ettercap2shell-livedissector.md` and `live-evidence/` for exact build
flags, pcap bytes, stack traces and the rung labels. Rung 3 now holds on the
real wire-parsing path; rung 4 remains scoped and partial; no rung 5, AV:A
unchanged.
