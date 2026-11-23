# Frontier brief — MiniSnmpd2Shell (candidate)

Candidate: **mini-snmpd ASN.1 BER length `size_t` underflow in
`decode_oid()` / `decode_str()` / `decode_ptr()`**, CVE-2026-59961 /
GHSA-c9g2-5ghh-8g8c. Grade: **rungs 1/2/3 ESTABLISHED in an extracted
harness; scoped rung 4 (chosen read extent, chosen adjacent bytes recovered)
and a real loopback daemon rung-2 reachability observation**. No wire-level
ASan report, no control-flow hijack, no command execution. Produced 2026-11-23
in the frontier wake starting 02:05:22Z. This is a research find, not an
admission; the operator decides targets. Harness, pins and wire scripts:
`lab/frontier/mini-snmpd/`, provenance in `PROVENANCE.md`.

## Verified ground truth

- Sources read this wake (read-only provisioning; all process tests on
  plant-started loopback instances): MITRE CVE JSON, maintainer GHSA HTML,
  fix commit metadata and `.patch`, pinned raw `protocol.c` at the fix and its
  parent, pinned `mini-snmpd.h`, and the v1.7 release commit spot check.
- CNA GitHub_M; CVE published 2026-11-18T21:15:50Z (GHSA itself displays Jul
  10, 2026 — both dates kept). HIGH 8.2,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H`, CWE-125 via CWE-191.
  Affected `< 1.7`, fixed 1.7 (release commit `6894e33e`). CISA SSVC:
  `Exploitation: poc`, `Automatable: yes`, `Technical Impact: partial`.
  Reporter credited on the GHSA: seiyaibuki0523.
- Claimed primitive: one SNMP request to UDP/161 with an inner OID/string TLV
  declaring a BER length larger than the datagram. `decode_len()` caps BER
  lengths at 0xFFFF but not against remaining packet size; the three decode
  helpers evaluate `*pos >= (size - len + 1)` in `size_t`. With `len > size`
  the bound wraps to a huge value, the guard is bypassed and the decoder
  reads up to ~63 KB past the 2048-byte `client->packet`. Parsing happens
  before the community string is compared, so no authentication is needed.
  The CNA claims DoS plus potential adjacent-heap disclosure; disclosure
  beyond the demonstration below stays a claim.
- This is the same class as CVE-2020-6058/6059, in three parser functions the
  2020 fix did not reach (advisory statement, not independently checked).

## Source-bound mechanism (pinned bytes and fix hunk)

Pinned vulnerable `protocol.c` at fix parent `b5322437` (SHA-256
`4bd06467…b10e42`) and fixed at `5419bc38` (`eeb05d95…4cb2`) differ by exactly
the four-line fix. In the vulnerable file:

- `decode_len()` at `:58–133` reads a one-byte BER length or a two-byte
  long-form length up to 0xFFFF; it never compares `len` with `size - *pos`.
- `decode_oid()` at `:190–256`, `decode_str()` at `:175–187` and
  `decode_ptr()` at `:259–270` all open with
  `if (*pos >= (size - len + 1)) { ... return -1; }`. Sibling
  `decode_int()` (`:136`) and `decode_cnt()` (`:157`) already use
  `if (len > size || *pos >= (size - len + 1))`.
- `decode_snmp_request()` decodes the community through `decode_str()` at
  `:313–322` with a `len < 64` size check, but the OID at `:412–421` has only
  `type == BER_TYPE_OID && len >= 1` before `decode_oid()` — that is the
  network-reachable limb for an oversized declared length.
- Fix `5419bc38` adds `len > size ||` to those three guards and widens
  `decode_ptr`'s `int len` to `size_t`.

With `size=2048`, `len=4000`, `pos=8`, the vulnerable bound is
`18446744073709549665`, greater than `size`, so `8 >= bound` is false and the
walk starts; read end is offset 4007, i.e. 1960 bytes past the logical packet.

## Local evidence

Harness `lab/frontier/mini-snmpd/harness/{driver.c,run.sh}` re-extracts the
verbatim `decode_oid` and `decode_str` slices from both pinned files on every
run and asserts five source/patch/driver hashes and four slice hashes. Three
working-tree runs plus a clean `/tmp` replay each gave **PASS=43 FAIL=0**;
normalized trace SHA-256
`0146b9b59168bb92ad4d725d7b1f162aa6de47661674f0086a0bf02e838e9859`
(hex addresses, PIDs, frame numbers and source paths removed). gcc 13.3.0 and
clang ASan; fixed and safe controls pass on both.

- **Rung 1 (trigger):** underflow arithmetic printed above; the fixed variant
  has the new guard asserted in its verbatim slice.
- **Rung 2 (state failure):** in a plain 8192-byte workspace, the decoder
  walks to `POS_AFTER=4007` and fills 18 OID subids from a logical 2048-byte
  packet; the fixed variant returns `RC=-1`, `POS_AFTER=8`, zero subids.
- **Rung 3 (ASan):** gcc and clang report `heap-buffer-overflow`,
  `READ of size 1`, `0 bytes after 2048-byte region`, frame `decode_oid`;
  fixed ASan and in-bounds safe inputs are clean.
- **Rung 4 (scoped):** canary bytes past the logical packet at offset 2048
  land byte-exact in `SUBID2_HEX` — 0x5a in one run, 0x3c in another. The
  attacker chooses the declared length and hence the read extent; the bytes
  read are whatever the adjacent heap holds. This is chosen-offset/observed-
  byte control in a direct-call harness, not a live daemon disclosure proof.
- **Real loopback daemon (rung-2 reachability, not rung 3):** ASan builds of
  both pinned trees were started by this plant on 127.0.0.1 ports 16161/16162
  and sent a 2048-byte SNMP GET declaring OID length 0xffff. Vulnerable:
  `overflow for OID byte` and a failed request — the oversized length reaches
  the vulnerable helper. Fixed: `underflow for oid` — rejected before the
  walk. A 35-byte in-bounds GET is handled cleanly by both.
- **Negative result preserved:** ASan does not report in the live daemon:
  `client->packet` is an array inside a larger global struct, so the first
  bytes past offset 2048 are neighbouring fields, not a redzone, and the
  20-subid cap stops the walk. The direct-call harness uses a heap packet of
  exactly 2048 bytes to expose the redzone crossing.

## Feasibility assessment (tractability ranking)

High tractability: tiny C daemon, public fix commit and release, two-helper
verbatim harness, and a real loopback daemon that reaches the branch. Ranked
ahead of the alternative finds screened this wake (mini-snmpd is AV:N and
pre-auth; ettercap's merged `gg_get_version` heap WRITE is AV:A and a sniffer
parser; FRRouting bgpd needs a heavy build). Cheapest next step toward a
stronger rung 4: use gdb on the plant-started daemon to read `pos` and the
first bytes past `client->packet` at the subid-cap branch, proving a chosen
datagram reads a chosen offset into adjacent struct memory; then build a
variant with a heap-allocated packet only if a wire-level ASan report is
needed (that variant is instrumented, not verbatim upstream bytes). No rung-5
claim is in scope: CWE-125 read, no pointer/marker/command evidence.

## Disposition / handoff

Stage as its own target mind (brief, charter/seed wall, two-pane window,
registry, operator DM). Frontier owns no further work on this target.
Mind-changers: the OID call path proves unreachable from a real request, the
fix does not apply to the shipped 1.7 release, or the chosen-byte result is
shown to come only from harness scaffolding.
