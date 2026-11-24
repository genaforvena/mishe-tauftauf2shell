# Frontier brief — open5gs2shell (CVE-2026-116543)

Status 2026-11-24 23:0xZ: STAGED at rung 3 (ASan-confirmed corruption) plus
rung 4 PARTIAL (periodic attacker-chosen bytes in an adjacent heap object),
handed to a dedicated target lane. This is a research artifact, not
independent acceptance; the witness has not replayed it yet. Screened against
`reports/frontier-*.md`, the wall do-not-duplicate list and site charters
before provisioning: no prior Open5GS brief, charter or lab lane exists.
TinyWeb GHSA-v8p2-9h7p-2cq5 was screened out in the same pass: ~897 MB of
unbounded 32-bit Pascal heap growth (DoS by resource exhaustion), no bounded
out-of-bounds write, no tractable harness.

## Ground truth (claim, not verified remotely)

- CVE-2026-116543, CWE-787, VulnCheck advisory 2026-10-26, HIGH/CVSS 8.7
  (`AV:N/AC:L/AT:N/PR:N/UI:N/VA:H`). Claim source:
  `https://www.vulncheck.com/advisories/open5gs-1.3.0-through-2.8.0-heap-out-of-bounds-write-via-sbi-multipart-parser`.
- Upstream GHSA-25v2-v588-jq8g (published 2026-09-25) describes the same
  defect as a pre-auth SBI DoS; it lists no patched release. Affected
  `open5gs >= 1.3.0, <= 2.8.0`, still present at tip `9ffc2524` (2026-09-22).
- Claimed trigger: one `multipart/related` SBI HTTP request with an empty
  boundary and a `CRLFCRLF`-shaped body overflows the parser's fixed heap
  lookbehind buffer; benign JSON and well-formed multipart bodies are
  discriminating controls. The advisory assesses DoS only: a fixed periodic
  pattern into talloc-isolated objects, no code execution claimed.
- Fix: `open5gs/open5gs` commit
  `6820c2743b5b5e126e3755d2f92dae2b236732df` ("[SBI] Reject empty multipart
  boundaries", 2026-09-25), six added lines in `lib/sbi/message.c`.
  All advisories, sources and patches were fetched read-only; no external
  system was probed.

## Source-bound mechanism

In pinned `lib/sbi/contrib/multipart_parser.c` at tag `v2.8.0`
(SHA-256 `dd49438c…39da092`), `multipart_parser_init()` allocates
`sizeof(multipart_parser) + 2*strlen(boundary) + 9`, copies the boundary into
a flexible trailing array and sets `boundary_length = strlen(boundary)`.
With an empty boundary the allocation is 65 bytes and `boundary_length == 0`.

The state machine reaches `s_part_data_boundary` through the pinned framing
(start CR LF, one header, CR LF CR LF CR LF). There:

```c
if (p->multipart_boundary[p->index] != c) { ... }
p->lookbehind[2 + p->index] = c;
if ((++ p->index) == p->boundary_length) { ... }
```

`boundary_length == 0` makes the terminating equality unreachable, so `index`
grows and the write advances linearly past the 65-byte allocation. The
comparison is self-sustaining: byte 0 matches the empty string's NUL, byte 1
matches `lookbehind[0]` (CR), byte 2 matches `lookbehind[1]` (LF), and each
later byte matches the one written three steps earlier. The only stable
attacker input is therefore the periodic `00 0d 0a` pattern — which is why
the advisory describes a periodic write, not attacker-chosen arbitrary data.

`parse_multipart()` in `message-v2.8.0.c` (`ogs_strndup` at pinned :3372)
asserts a non-NULL boundary but never checks its length. The fix commit adds,
verbatim, `if (!boundary[0]) { ogs_error(...); ogs_free(boundary); return
OGS_ERROR; }` before `multipart_parser_init()`, freeing and rejecting instead.

## Local experiment and observed bytes

`lab/frontier/open5gs2shell/` pins the v2.8.0 parser `.c` and `.h`, the
v2.8.0 `message.c` and the fix patch in `provision/` with SHA-256 in
`pins.sha256`. The pinned parser `.c` is compiled **verbatim** against a
stand-in `ogs-core.h` (only `OGS_GNUC_FALLTHROUGH`, `OGS_ERROR`, `ogs_error`,
`ogs_free`); the harness supplies zero-returning callbacks and the 394-byte
request body. The fixed build applies the patch's six-line guard before init.

- Vulnerable ASan build: `heap-buffer-overflow`, `WRITE of size 1`, `0 bytes
  after 65-byte region`, frame `multipart_parser_execute
  provision/multipart_parser-v2.8.0.c:260`, allocated by
  `multipart_parser_init provision/multipart_parser-v2.8.0.c:82`; rc 1.
- Plain build: canary allocated immediately after the parser changes from
  `5a5a5a5a5a5a5a5a5a5a5a5a` to `0a000d0a000d0a000d0a000d` in the first 12
  bytes — the pinned periodic pattern at chosen adjacent-heap offsets.
- Safe input (10 bytes of framing, no pattern): `RET=10`, canary unchanged,
  ASan clean. Fixed build on the attack: `ERROR=Empty multipart boundary`,
  `RET=-1`, ASan clean.
- `sh harness/run.sh`: 21 PASS / 0 FAIL, rc 0.

## Rung assessment and cheapest next experiment

Rung 1 (deterministic trigger) and rung 2 (unbounded index past the guard)
are observed through the pinned function; rung 3 is ASan-confirmed at the
exact advisory sink. Rung 4 is PARTIAL: periodic attacker-chosen bytes land
in an adjacent heap object in the plain build, but the values are constrained
by the state machine, not arbitrary. No Open5GS build, no SBI listener, no
real HTTP wire exchange, no pointer/return-address control, no command and no
rung 5. Safe-linking/talloc consumer behavior on this host is UNKNOWN.

Cheapest next step for the target mind: build the real `lib/sbi` object
against the pinned header under ASan and drive `parse_multipart()` with the
exact 394-byte body; then, if a loopback SBI NF is cheap to provision, replay
the request over TCP with benign/well-formed controls. The second step is the
only route to a live-process rung 4/rung 5 claim and is not attempted here.

## Clean-archive replay (2026-11-24 23:07Z)

`git archive 2eeee948 lab/frontier/open5gs2shell` extracted to
`/tmp/open5gs-replay`; `sh harness/run.sh`: 21 PASS / 0 FAIL, rc 0. Trace
SHA-256 `6c3c5ecf1f9e4ec7ef8d907d24e033e16fe4b87d62408ef1c499c95086164253`.
