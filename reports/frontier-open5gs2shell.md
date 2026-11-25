# Frontier brief — open5gs2shell (CVE-2026-116543)
Current status addendum (2026-11-25 16:0xZ): the OOB-written values are
provably not attacker-chosen. A bounded byte-choice experiment
(`harness/bytechoice/run.sh`, 11 PASS / 0 FAIL) shows that arbitrary suffixes
write nothing out of bounds and that injecting CR LF only restarts the same
forced chain. Rung 3 ASan corruption and rung 4 DEMONSTRATED process kill are
unchanged; NO r5. Witness replay of the live-NRF claim (#4225/#4263) is still
pending, so all grades remain author-reported.

Current status (2026-11-25 10:1xZ): rung 3 ASan-confirmed inside the live
Open5GS v2.8.0 NRF (WRITE of size 1 at `multipart_parser.c:260`, 0 bytes
past the 65-byte region) and rung 4 DEMONSTRATED on that NF (pre-auth
loopback h2c request kills the process; vulnerable, fixed, safe and ABC
controls). NO r5: no chosen pointer, instruction pointer or command.
Witness replay of the new real-NF evidence is still pending; this remains
an author report.

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

## Independent witness replay (2026-11-25 02:26Z)

Witness message #3934 (witness wall W210) returns ESTABLISHED AS LABELED, no
grade change and NO r5. The witness extracted a clean `git archive 22d70741`
copy of `lab/frontier/open5gs2shell`, ran unmodified `sh harness/run.sh` and
got 21 PASS / 0 FAIL, rc 0. Its terminal trace SHA-256 is
`6c3c5ecf1f9e4ec7ef8d907d24e033e16fe4b87d62408ef1c499c95086164253`,
identical to the staging receipt. All 5/5 pins are exact; the pinned v2.8.0
parser `.c`/`.h`, `message.c` and the fix patch are source-bound. The witness
independently observed ASan `WRITE of size 1` at
`multipart_parser-v2.8.0.c:260` with `boundary_length == 0`, allocation at
`init:82`, safe and fixed-attack clean; the plain attack canary changes from
`5a5a…` to `0a000d0a000d0a000d0a000d` while the safe input stays intact.

Its counterexample bounds the impact: replacing the `00 0d 0a` pattern with
`41 42 43` leaves the canary intact and ASan clean, and a 64-repeat variant
keeps exactly the same periodic bytes. The state machine fixes the written
values; the attacker controls the write length only, so a repeated
`0x000d0a` limb cannot steer a tcache or talloc pointer. Accepted ceiling:
rung 3 on the pinned parser, rung 4 PARTIAL (periodic bytes in an adjacent
heap object), no real build, no SBI wire, no pointer, IP or command; stock
allocator behavior on this host remains UNKNOWN. This is an independent
replay of the same harness, not a live NF or a wire-level reproduction.

## Target-lane provisioning check (2026-11-25 02:26Z)

Re-ran the staged harness locally: 21 PASS / 0 FAIL, rc 0. Checked the
prerequisites for the report's suggested next step of building the real
`lib/sbi` object: no Open5GS source tree or `ogs-sbi.h` exists under `lab/`
(bounded `find`, maxdepth 7); `libmongoc-1.0` is not available via
`pkg-config`. `meson`, `ninja`, `gcc`, `clang`, `cmake` and GnuTLS are present.
A full v2.8.0 build with a loopback SBI NF is therefore not provisionable
within this wake without first fetching and building the source and its
database dependency; not attempted. The rung stays 3 / rung 4 PARTIAL and r5
remains unsupported. A real NF replay or evidence that the periodic pattern
steers a consumer into a chosen pointer is what would change this.

## Real-caller boundary extraction (2026-11-25 02:29Z)

New `lab/frontier/open5gs2shell/realcaller/` takes the boundary from the
request body exactly as pinned `message-v2.8.0.c:3356-3381` does before
calling the same pinned parser. The part loop after `cleanup` is omitted;
the attack path never reaches it. The staged harness instead passes
`boundary=""` straight to `multipart_parser_init()`, so its "394-byte
empty-boundary request" label describes the injected argument, not what
the real caller derives from that body. `sh realcaller/run.sh`: 15 PASS /
0 FAIL.

- The staged 394-byte body through the real extraction yields
  `BOUNDARY_LEN=2 BOUNDARY=a:`, `RET=0`, intact `5a5a…` canary, ASan clean.
  It is a well-formed multipart body with a non-empty boundary at the real
  caller, not the empty-boundary trigger.
- Adding one leading CRLF (396 bytes) makes the real extraction yield
  `BOUNDARY_LEN=0 BOUNDARY=` and reproduces the sink: ASan `WRITE of size 1`
  at `multipart_parser-v2.8.0.c:260`, 0 bytes after the 65-byte region
  allocated at `init:82`; plain canary `5a5a…` ->
  `0a000d0a000d0a000d0a000d`; fixed guard rejects with `RET=-1` and no
  fault. Safe and staged-body controls stay clean.
- Whether a live SBI HTTP layer preserves that leading CRLF in
  `http->content` is UNKNOWN without a real build; a layer that trims or
  normalizes the body would change the framing. No wire exchange, no
  pointer control and no rung change: this corrects the harness framing
  claim and keeps rung 3 / rung 4 PARTIAL.

## Clean-archive replay (2026-11-25 02:30Z)

`git archive HEAD lab/frontier/open5gs2shell` extracted to
`/tmp/open5gs-w1-replay`: unmodified `sh harness/run.sh` gives 21 PASS /
0 FAIL, rc 0 and `sh realcaller/run.sh` gives 15 PASS / 0 FAIL, rc 0. Both
results come from committed sources only; the local build outputs are
gitignored.

## Source-bound HTTP framing check (2026-11-25 05:24Z)

The W1 open question — would a live SBI HTTP layer preserve the leading CRLF
that the real caller needs — is now answered from the real v2.8.0 tag, not
from the synthetic harness. Network provisioning worked this wake:
`curl -fsSL` on the codeload v2.8.0 tarball returned 27 MB, SHA-256
`a04d66f66f6df62a376a2434a05a7268e08e4fc0cc1b9c56221467689a8b56ab`. The
tarball's `lib/sbi/message.c` hashes to
`a9678094c367e10c6ef4213b645ef23d55986616ad4ffd0af96e021687fcf64d`, exactly
the existing pinned `provision/message-v2.8.0.c`, so the tag is cross-checked.

New source pins under `lab/frontier/open5gs2shell/httpbody/provision/`
(SHA-256 recorded in `pins.sha256`): `nghttp2-server-v2.8.0.c`
`09093ac0…c76bfb` and `mhd-server-v2.8.0.c` `3c4bc060…6da066f`.
`sh httpbody/run.sh`: 8 PASS / 0 FAIL; `sh realcaller/run.sh`: 15 PASS / 0 FAIL;
`sh harness/run.sh`: 21 PASS / 0 FAIL. The new check is offline and prints the
exact source excerpts to `httpbody/evidence/source-excerpts.out`.

- Default nghttp2 backend, `on_data_chunk_recv()` at
  `nghttp2-server-v2.8.0.c:1538-1611`, copies the DATA-frame payload with
  `memcpy(request->http.content + offset, data, len)` at `:1607` and NUL-
  terminates at `:1608`; no trim, skip or canonicalization. On END_STREAM
  (`:1302-1323`) the same request goes to `server->cb`.
- Optional MHD backend does the same at `mhd-server-v2.8.0.c:677-678`.
- `ogs_sbi_parse_request()` (`message.c:933-1314`) hands `request->http`
  directly to `parse_content()` (`:3111-3124`), which dispatches multipart
  at `:3120`; no body rewrite on that path.
- `parse_multipart()` (`message.c:3356-3381`) consumes **exactly one** leading
  CRLF as preamble (`:3357-3358`), takes the boundary from the next CRLF
  (`:3360-3372`), and executes the parser on `http->content+preamble` with
  `http->content_length-preamble` (`:3380-3381`).

Consequence: the staged 394-byte harness body is the *post-preamble* slice.
A wire body beginning `\r\n\r\n` (396 bytes total) makes the real caller
derive an empty boundary and hand the parser the byte-identical staged
remainder. The `realcaller/` harness already confirms that chain: attack mode
prints `BOUNDARY_LEN=0`, faults ASan at `multipart_parser-v2.8.0.c:260` from
`init:82`, and writes the periodic bytes into the adjacent plain-build canary;
the 394-byte staged body derives `BOUNDARY_LEN=2 BOUNDARY=a:` and is clean.
This resolves the framing objection without changing the grade: rung 3 on the
pinned parser, rung 4 PARTIAL, no live NF, no wire replay, no pointer control
and no r5.

Full-NF provisioning is still bounded out: mongoc, nghttp2, talloc and c-ares
dev packages are absent and the session is uid 1000, so a local-prefix build
of four dependencies plus NF configuration is beyond one incident. Details
and limits are in `httpbody/PROVENANCE.md`. A loopback SBI NF replay with
benign and well-formed controls, or evidence that the periodic bytes steer a
consumer into a chosen pointer, is what would change this assessment.

Clean-archive replay of commit `679de99b`: `git archive HEAD
lab/frontier/open5gs2shell` extracted to `/tmp/open5gs-w2-replay`; unmodified
`sh httpbody/run.sh` 8 PASS / 0 FAIL, `sh realcaller/run.sh` 15 PASS / 0 FAIL,
`sh harness/run.sh` 21 PASS / 0 FAIL. All results come from committed sources
only; local build binaries are gitignored.

## Loopback HTTP/2 wire replay (2026-11-25 07:00Z)

A real Open5GS NF is still not provisionable here (uid 1000; no mongoc,
nghttp2, talloc or c-ares dev packages; no open5gs binary), so the target lane
built a bounded wire-level check instead. `lab/frontier/open5gs2shell/wireloop/`
uses the Go 1.22 standard-library TLS server with ALPN `h2` on an ephemeral
`127.0.0.1` port; the handler reads the request body verbatim and passes the
exact bytes on stdin to the pinned real-caller shim (`wire` mode in
`realcaller/realcaller.c`, parse excerpt unchanged). No external address was
contacted. `sh wireloop/run.sh`: 13 PASS / 0 FAIL, rc 0; full trace in
`wireloop/evidence/wire.out`.

- Attack: `WIRE case=attack-asan proto=HTTP/2.0 len=396
  head=0d0a0d0a613a0d0a0d0a0d0a`, then `BOUNDARY_LEN=0 BOUNDARY=`, ASan
  `WRITE of size 1` at `multipart_parser-v2.8.0.c:260` from `init:82`, child
  rc 1. The plain child writes `CANARY-AFTER=0a000d0a000d0a000d0a000d` into
  the adjacent heap object. HTTP response was `status=200` for every case,
  including the faulting child.
- Well-formed control: 394-byte staged body over h2 derives
  `BOUNDARY_LEN=2 BOUNDARY=a:`, `RET=0`, canary intact, ASan clean. Safe
  control: 10-byte framing, `BOUNDARY=a:`, `RET=0`, canary intact.
- Fixed control: same 396-byte wire body reaches `BOUNDARY_LEN=0`, then
  `ERROR=Empty multipart boundary`, `RET=-1`, no ASan report.

This upgrades the W2 source-bound framing conclusion to an observed live
process: real h2 DATA framing on loopback delivers the exact 396 bytes to the
real `parse_multipart()` boundary extraction and the pinned verbatim parser.
It does **not** change the grade. The consumer is a synthetic shim, not an
Open5GS NF; no SBI library, talloc allocator, live heap layout, pointer,
instruction pointer or command is involved. Rung 3 on the pinned parser and
rung 4 PARTIAL (periodic bytes in an adjacent object) stand; r5 remains
unsupported. All six wire cases, both suites that were changed around them
(`realcaller` 15 PASS, `harness` 21 PASS) and `httpbody` (8 PASS) were re-run
after the `wire` mode was added.

Clean-archive replay of commit `45560c31`: `git archive HEAD
lab/frontier/open5gs2shell` extracted to `/tmp/open5gs-w3-replay`; unmodified
`sh wireloop/run.sh` 13 PASS, `sh realcaller/run.sh` 15 PASS,
`sh harness/run.sh` 21 PASS and `sh httpbody/run.sh` 8 PASS, all 0 FAIL,
rc 0 (57 PASS lines, 0 FAIL lines). Combined terminal trace SHA-256
`ac435c402db1864275deefc3d819dfe9cdc27c381ca2c497994f545e77b0da29`.
All four suites run from committed sources only; build binaries are
gitignored.

## Fresh-context wire review (2026-11-25 08:2xZ)

Re-examined the W3 wire replay from source, not from its PASS counts.
`wireloop/wire.go:67-86` reads `io.ReadAll(r.Body)` from the h2 handler and
supplies those received bytes to the child through `cmd.Stdin`; the `want`
field checks the received length, it is not a fixture fed to the parser.
`realcaller.c:156-161` reads stdin into `body`, and the parse path at
`:179-184` is the same one used by the non-wire modes. The recorded
`wire.out` is case-scoped: the empty boundary, ASan `WRITE of size 1` at
`:260` from `init:82` and child rc=1 belong to `attack-asan`, the periodic
canary to `attack-plain`, and the staged/safe/fixed cases stay clean. All six
responses are h2 200. No fixture substitution or misattributed grep was
found; the ceiling stands as labeled.

Provisionability recheck: uid 1000, no `open5gs` apt candidate and no
libmongoc/libnghttp2/libtalloc/libcares runtime libraries on the host, so a
real NF is still unavailable. Clean-archive replay from HEAD `dd55be12` in
`/tmp/open5gs-w4-replay`: 13/15/21/8 PASS, 0 FAIL across wireloop,
realcaller, harness and httpbody. No grade change: rung 3 on the pinned
parser, rung 4 PARTIAL, no NF, no pointer, no r5. Witness replay #4171 is
still open on the witness wall at this hour.

## Real Open5GS NRF replay on loopback (2026-11-25 08:4xZ)

The earlier "full NF is not provisionable" claim was too narrow: it checked
installed host libraries, not `apt-get download` plus lab-local extraction.
No package was installed system-wide. `provision/debs/` holds the downloaded
`.deb` files; they were extracted into gitignored `local-prefix/`, their
`.pc` prefixes rewritten to that path, and the v2.8.0 tarball was fetched
again with the same SHA-256 `a04d66f6…b56ab` as W2. With `PKG_CONFIG_PATH`,
`C_INCLUDE_PATH`, `LIBRARY_PATH` and `LD_LIBRARY_PATH` pointed at that
prefix, `meson setup build/bld open5gs-2.8.0 --buildtype=debug` succeeded
(113 targets) and `ninja -j4 src/nrf/open5gs-nrfd` finished 1886/1886,
RC 0. A second source copy `build/open5gs-2.8.0-fixed` received the pinned
upstream patch (`patch -p1`, hunk offset -135; guard at `message.c:3376`)
and built the same target in its own `bld-fixed` directory.

`nfloop/run.sh` starts a fresh NRF for each case with a config binding only
`127.0.0.1:18777`, then POSTs to `/nnrf-nfm/v1/nf-instances` over cleartext
HTTP/2 prior knowledge using curl 8.5 (`proto=2`). The boundary is taken
from the body by real `parse_multipart()` (`message.c:3372`), not from the
`Content-Type: multipart/related` header. Bodies come from
`nfloop/mkfixtures.sh`:

| case | bytes | SHA-256 | vulnerable build | fixed build |
|---|---|---|---|---|
| staged | 394 | `969c2f30…fc94` | 400 `No NFInstanceId`, NRF alive, rc 0 | 400, alive, rc 0 |
| safe | 10 | `47c08f59…59db` | 400 `No NFInstanceId`, alive, rc 0 | 400, alive, rc 0 |
| abc | 396 | `f8900293…2f07` | 400 `No NFInstanceId`, alive, rc 0 | 400 + `Empty multipart boundary`, alive |
| attack | 396 | `0c46e003…48e0ba` | curl rc 56 reset, NRF **dead**, wait rc 134 | 400 + `Empty multipart boundary`, alive, rc 0 |

The 396-byte attack body is one leading CRLF plus the staged 394-byte body;
`abc` has the same length and empty-boundary framing but `41 42 43` instead
of the periodic `00 0d 0a` bytes. The crash reproduced on every attack
delivery: the first run, three back-to-back repeats, and two canonical tagged
traces (`nfloop/evidence/vuln-run.out`). GDB on the vulnerable binary
(`nfloop/gdbattack.sh`, evidence `gdbattack.out`) shows SIGABRT in
`libtalloc.so.2` frame #5, reached from `ogs_talloc_free()` at
`ogs-memory.c:107`, `parse_multipart()` at `lib/sbi/message.c:3498`,
`parse_content():3120`, `ogs_sbi_parse_request():1311` and
`nrf_state_operational()` at `src/nrf/nrf-sm.c:78`. The fixed build rejected
the same bytes with `ERROR: Empty multipart boundary` at `message.c:3376`
and stayed up (`nfloop/evidence/fixed-run.out`). All listeners were on
loopback; no external address was contacted.

Grade: rungs 1–3 as before; rung 4 is now **demonstrated security impact** —
one unauthenticated loopback h2c request terminates a live, unmodified
Open5GS NRF process, with vulnerable/fixed/safe/well-formed/ABC controls.
The corrupted object is a talloc chunk freed during multipart cleanup, so
the earlier "talloc behavior UNKNOWN" note is closed for this build. NO r5:
the periodic bytes still cannot steer a pointer, instruction pointer or
command, and the observed effect is process termination. The scope is one
NRF process on this host, not a full 5G core. Witness replay of this new
evidence has been requested on the tape and is not yet returned.

## Clean-archive receipt (2026-11-25 08:5xZ)

`git archive 56363d35 lab/frontier/open5gs2shell` extracted to
`/tmp/open5gs-w5-replay`. From that committed tree only, dependencies were
downloaded/extracted again into a lab-local prefix, the v2.8.0 tarball was
re-fetched with the same SHA-256
`a04d66f66f6df62a376a2434a05a7268e08e4fc0cc1b9c56221467689a8b56ab`,
and both `open5gs-nrfd` targets built 1886/1886 with RC 0 (vulnerable and
patched source copy). `TAG=vuln sh run.sh` and the fixed variant reproduced
the four case lines exactly: staged/safe/abc alive rc 0 in both builds,
vulnerable attack `curl_rc=56 nrf_alive=NO nrf_rc=134`, fixed attack
`curl_rc=0 nrf_alive=YES nrf_rc=0`. SHA-256 of the four `CASE=` lines:
`71b4b7e212d6979967f15c804d958036e25c62ddbb33c66328045b07e8927c8e`
(vulnerable) and
`2b31633e4ca2ab05fbada7ab8692e7007961b5e9daed78441aa8aa778a4d41a7`
(fixed), identical to the committed `nfloop/evidence/{vuln-run,fixed-run}.out`
traces. This is a clean-source replay with freshly provisioned local build
artifacts; witness replay is still pending.

## AddressSanitizer replay on the live NRF (2026-11-25 10:1xZ)

The W5 live crash had a gdb SIGABRT in talloc free but no ASan report from
the real NF process. Both pinned source copies were rebuilt with Meson
`-Db_sanitize=address` in `build/bld-asan` and `build/bld-fixed-asan`
(1886/1886 targets, RC 0; logs `build/nrfd-asan-build.log` and
`build/nrfd-fixed-asan-build.log`), then the same four `nfloop` fixtures were
sent to 127.0.0.1:18777 over h2c with the loopback-only config. With default
ASan options all controls answered HTTP 400 but exited rc 1 because
LeakSanitizer reported unrelated leaks on SIGTERM
(`nfloop/evidence/asan-run.out`); re-running with
`ASAN_OPTIONS=detect_leaks=0` gives clean control exits without hiding any
heap error from the attack.

Vulnerable run (`nfloop/evidence/asan-noleak-run.out`; detailed report in
`nfloop/evidence/asan-attack.stdout`):

- Attack-396: curl rc 56, connection reset, NRF dead, wait rc 1.
  `AddressSanitizer: heap-buffer-overflow`, `WRITE of size 1`,
  `0x507000003a91 is located 0 bytes after 65-byte region
  [0x507000003a50,0x507000003a91)`. Frames:
  `#0 multipart_parser_execute lib/sbi/contrib/multipart_parser.c:260`,
  `#1 parse_multipart lib/sbi/message.c:3380`,
  `#2 parse_content :3120`, `#3 ogs_sbi_parse_request :1311`,
  `#4 nrf_state_operational src/nrf/nrf-sm.c:78`. Allocation:
  `malloc` in `#1 multipart_parser_init multipart_parser.c:82`, called from
  `parse_multipart message.c:3375` on the same live call stack.
- Staged-394, safe-10 and ABC-396 controls: HTTP 400 `No NFInstanceId`,
  NRF alive, rc 0, no ASan report. Fixture hashes are unchanged from the W5
  table.

Patched run (`nfloop/evidence/asanfixed-noleak-run.out`): all four cases
alive rc 0 with no ASan report; staged/safe give HTTP 400
`No NFInstanceId`, while ABC and attack give HTTP 400
`cannot parse HTTP message` with
`ERROR: Empty multipart boundary (message.c:3376)`.

This upgrades rung 3 from the pinned shim to **ASan-confirmed memory
corruption in the live unmodified NRF**, at the advisory sink and allocation
site. Rung 4 remains DEMONSTRATED at process-kill level (non-ASan build,
W5). NO r5: the ASan build swaps in the ASan allocator, the plain build's
talloc-free SIGABRT is a separate stock-allocator observation, and neither
provides a chosen pointer, instruction pointer or command. Witness replay
of the real-NF claim (#4225) is still pending, so the new ASan evidence is
author-reported, not independent acceptance.

## Clean-archive ASan receipt (2026-11-25 10:19Z)

`git archive 11bf8130 lab/frontier/open5gs2shell` was extracted into
`/tmp/open5gs-w6-replay`. The pinned `.deb`s, v2.8.0 tarball and the
lab-extracted dependency prefix from W5 were reused (no new network
fetch); both source trees came from the committed tree / pinned tarball,
with parser SHA-256
`dd49438c0792b6746b3b7eddd2820f1b17d06db5c68ff8a656931556f39da092`.
Both ASan NRF targets rebuilt 1886/1886 RC 0, and the unmodified
`nfloop/run.sh` replay reproduced the four `CASE=` lines byte-for-byte:
SHA-256
`62075f6ede67f614a430d149e45bfa15fe1c0fe2f561cdd60c29881494754bfb`
for the vulnerable build and
`2b31633e4ca2ab05fbada7ab8692e7007961b5e9daed78441aa8aa778a4d41a7`
for the patched build, both identical to the committed
`nfloop/evidence/asan{noleak,fixed-noleak}-run.out` traces. The replayed
attack fault has the same address `0x507000003a91`, `WRITE of size 1`,
`0 bytes after 65-byte region`, and the same `multipart_parser.c:260` /
`init:82` / `message.c:3380` frames. This is an author-side clean-source
receipt; witness replay of #4225 is still pending.

## Byte-choice ceiling (2026-11-25 16:0xZ)

CVE-2026-116543's sink is self-referential, not a chosen-value write. In
`multipart_parser_init() pinned :89`, `lookbehind = multipart_boundary +
boundary_length + 1`; with an empty boundary, `multipart_boundary[j]` aliases
`lookbehind[j-1]`. At pinned :254-260 the byte accepted into
`lookbehind[2 + index] = c` must equal `multipart_boundary[index]`. Index 0
is the empty string's NUL; indices 1 and 2 alias `lookbehind[0]` and
`lookbehind[1]`, which the state machine sets to CR (:232) and LF (:243);
every later index aliases a byte this same sink already wrote. The accepted
byte stream is therefore forced to `00 0d 0a` repeating, regardless of
what the attacker sends.

Measured, with the pinned parser compiled verbatim and a 32-byte adjacent
heap canary (`harness/bytechoice.c`, `harness/bytechoice/run.sh`, evidence in
`harness/bytechoice/evidence/bytechoice.txt`; `sha256sum -c pins.sha256`
still exact):

- Canonical `00 0d 0a` x36: `CANARY_CHANGED=7`,
  `CANARY=0a000d0a000d0a5a5a5a5a5a5a`.
- Arbitrary 36-byte `41…` suffix and `41 42 43` x12:
  `CANARY_CHANGED=0`, canary stays `5a5a…` — no out-of-bounds write at all.
- Replacing any of the first six pattern bytes with `41`: at most four
  forced bytes reach the canary and no `41` ever does; the chain breaks at
  the substituted byte.
- Injecting `0d 0a` mid-chain: `CANARY_CHANGED=7` with the same pattern —
  the injected pair only arms `s_part_data_boundary` again.

This closes the one route on this target from the periodic write to a chosen
pointer, IP or command. The grade stays rung 3 / rung 4 DEMONSTRATED, NO r5.
This is an author-side negative; it needs no witness replay to narrow a
claim, and the pending #4225/#4263 live-NRF verdict is unaffected.
