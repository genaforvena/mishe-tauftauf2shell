# Frontier brief: nDPI `ndpi_json_string_escape()` caller-buffer write (ndpi2shell)

**STAGED 2026-11-23 W161** — this brief, a direct-call rung-1..4 harness and a
live registered two-pane window (inner socket index 121, name `ndpi2shell`)
exist; seed wall `.mishe-tauftauf/walls/ndpi2shell.md`, registry entry and
staging DM are in place. Operator admission and an independent witness replay
are pending. Byte-exact pins and hashes: `lab/frontier/ndpi2shell/PINS.sha256`;
harness provenance, stubs, negatives and commands:
`lab/frontier/ndpi2shell/PROVENANCE.md`. Frontier owns no further work on this
target.

## 1. Verified ground truth

- Source claim: GHSA-c8vx-3h2j-4f8m / CVE-2026-86098, GitHub Advisory
  Database, Unreviewed, High 7.4, CWE-787, published 2026-09-05. It describes
  a heap buffer overflow in `ndpi_json_string_escape()` reachable with crafted
  TLS SNI, HTTP header or DNS name data, in nDPI versions before 6.0.
- Fix: commit `94e82c1de12323d992895830231865736a8abf2c` (2026-08-25),
  referenced by the advisory and fetched read-only. Its message reports the
  same primitive, names affected "nDPI <= 5.0, HEAD `ea3586e`", and claims
  ASan confirmation by the reporter. All of that is a claim reproduced here.
- Affected/fixed: the advisory claims fixed 6.0; only the fix commit was
  fetched, so the numeric fixed release is **UNKNOWN** pending a tag check.
  The vulnerable file was pinned at `94e82c1^` and the fixed file at
  `94e82c1`; no nDPI build was made.
- No external probe. Advisory and source fetches were provisioning only.

## 2. Source-bound mechanism and fix

Rendered line numbers are claims; pinned bytes live in
`lab/frontier/ndpi2shell/src/` and are sliced verbatim under `#line` by
`harness/run.sh`.

`ndpi_json_string_escape(const char *src, int src_len, char *dst, int
dst_max_len)` writes the opening quote at `:94` with no bounds check. Its loop
at `:96` tests `j < dst_max_len` once per source byte, but a 2-byte JSON escape
writes twice at `:106-107` and a 4-byte UTF-8 sequence writes four times at
`:155-158`. A guard that passes with `j == dst_max_len-1` therefore permits a
store at `dst[dst_max_len]`. After the loop, `:162` writes the closing quote
and `:163` stores the NUL at `dst[j+1]` — one byte beyond the quote and one
byte past the natural end — without any size check. With an 8-byte caller
buffer, a `/` escape at `j=7` stores chosen `0x2f` at offset 8, the quote at 9
and the NUL at 11; six printable bytes leave the quote at 7 and put the NUL at
offset 8.

Fix `94e82c1` rejects `dst_max_len < 3`, reserves two bytes with
`safe_max_len = dst_max_len - 2`, adds `j+N > safe_max_len` prechecks to every
escape branch, moves UTF-8 lookahead length checks before the byte reads,
writes the NUL at `dst[j]` (`:219`) and returns `-1` on overflow (`:222-225`).

## 3. Cheapest local experiment

Slice the pinned function bodies (`:90-166` vulnerable, `:90-226` fixed) into
a driver with a `u_char` typedef and exact-size heap destination. Four
scenarios: `baseline` (3 printable, 32-byte destination), `escape` (6 printable
+ `/`, 8-byte destination), `utf8` (4 printable + 4-byte UTF-8, 8-byte
destination), `nul` (6 printable, 8-byte destination). Plain builds append a
32-byte `0xa5` canary to expose post-size bytes; ASan builds allocate exactly
`dst_max_len`. Build with gcc and clang.

Commands (from `lab/frontier/ndpi2shell/harness/`): `./run.sh` verifies pins
and builds 8 binaries; `./check.sh` runs 32 invocations plus two gdb probes and
prints a normalized trace hash.

## 4. Observed evidence (this wake, direct-call harness)

- Rung 1: vulnerable `baseline` returns `rc=5`; `escape` and `utf8` return
  `rc=10`, `nul` returns `rc=8`, each having written past the 8-byte
  destination.
- Rung 2: fixed build returns `rc=-1` on all three attacks, leaves the canary
  at `a5 a5 a5 a5 a5 a5 a5 a5`, and produces no ASan report; baseline is `rc=5`.
- Rung 3: gcc and clang ASan both report `heap-buffer-overflow`, `WRITE of
  size 1` at pinned `ndpi_serializer.c.vuln:107` (escape), `:158` (4-byte
  UTF-8) and `:163` (off-by-one NUL), each with `EXIT=1`.
- Rung 4: plain vulnerable tail bytes at offsets `dst_max_len..+3` are
  `2f 22 a5 00` (escape), `80 22 a5 00` (utf8) and `a5 00 a5 a5` (nul) —
  chosen source bytes at chosen offsets, with the skipped canary byte showing
  the misplaced NUL. gdb at `:107` reports `J=8 C=0x2f`, and after return
  `x/8xb dst+8` shows `0x2f 0x22 0xa5 0x00`, matching. No pointer or control
  flow was exercised.
- `172 PASS / 0 FAIL` over 32 runs plus two gdb probes, three identical runs;
  trace `16060f55dfe944bf5e481a43e76034f6cd3d7acc159d561beaa067c8c97f7b5b`.
  Raw outputs in `lab/frontier/ndpi2shell/harness/evidence/`.

## 5. Ceiling and cheapest next rung

Direct calls with a stubbed typedef and driver-owned buffers. No nDPI build,
no serializer struct, no real packet, parser, socket or wire path, no pointer
chain, no benign marker execution, no command execution, no witness replay.
The advisory's TLS SNI / HTTP / DNS reachability is a claim; the reporter's own
patch text says internal callers over-allocate by 24 bytes, so this harness
reproduces the exact-size external public-API condition rather than an in-tree
caller.

Cheapest move toward a real consumer: build nDPI 5.0 with ASan, call the
public serializer through a small C program that passes an exact-size
`dst_max_len`, then trace which real dissector supplies untrusted strings and
whether any caller passes a tight buffer; feed crafted TLS SNI / HTTP / DNS
data to a loopback-only nDPI reader and preserve the negative if all in-tree
callers keep the +24-byte margin. Rung 5 is UNKNOWN.
