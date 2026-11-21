# Frontier brief — libwebsockets HTTP/2 HPACK path OOB write (Libwebsockets2Shell)

**Status: brief + harness COMPLETE, admitted by the operator 2026-11-21
12:25Z; witness W68 verdict ESTABLISHED AS CLAIMED at the labeled grade.**
Rungs 1/2/3 ESTABLISHED in an extracted, verbatim-pin harness; rung 4 shows
attacker-chosen bytes at chosen offsets just past a bounded header arena in an
instrumented collaborator only. A loopback real-build check (below) shows the
claimed long-`:path` route does **not** reach the past-end store in v4.3.10:
the real caller stops at the boundary. No real heap neighbour, pointer,
control-flow diversion or execution was observed — all stay UNKNOWN. The
advisory's "execute arbitrary code" is a claim to reproduce, not a result
obtained here.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-19773, ZDI-26-590 / ZDI-CAN-31036; CNA Zero Day
  Initiative. CVE record `dateReserved` `2026-08-13T17:33:16.820Z`,
  `datePublished` `2026-09-15T18:01:09.199Z`, `dateUpdated`
  `2026-09-16T03:57:34.021Z`; ZDI public release 2026-08-24 (scout-reported,
  not independently verified). Verbatim claim: "libwebsockets HTTP/2 HPACK
  Path Header Parsing Out-Of-Bounds Write Remote Code Execution Vulnerability
  ... allows remote attackers to execute arbitrary code ... Authentication is
  not required ... lack of proper validation of user-supplied data ... write
  past the end of an allocated buffer." CVSS 3.0
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 CRITICAL**; CWE-787. Finder
  Maher Azzouzi (TrendAI ZDI). Pins in
  `lab/frontier/libwebsockets2shell/src/cve19773.json` and
  `src/zdi-26-590.html`; sources
  <https://www.zerodayinitiative.com/advisories/ZDI-26-590/> and
  <https://osv.dev/vulnerability/CVE-2026-19773>.
- **Affected/fixed**: the CVE record names affected upstream commit
  `b4b5aed3903eaff09cd76a410f69bbe5dff66f8e`. Raw tag `v4.3.10` was verified
  vulnerable here; raw tag `v5.0.0` carries the guard. The fix is commit
  `824151862f37bc72f46d9a3e01d5b9408d313a0b` ("zdi-can-31036: h2 bounds check
  on server", 2026-07-03), adding exactly three lines to `hpack.c`; pinned in
  `src/fix19773.patch`. A scout-reported Debian backport to 4.3.5 is
  UNVERIFIED here. Do not call v4.3.10 fixed.
- **Raw sources**: `lib/roles/h2/hpack.c` at `v4.3.10` (affected) and `v5.0.0`
  (fixed), plus the patch, CVE JSON and ZDI page — five SHA-256 pins listed in
  `lab/frontier/libwebsockets2shell/PROVENANCE.md`, re-verified by
  `gen_driver.py` on every run (exits 1 on pin drift via `sys.exit(str)` at
  `gen_driver.py:29`). The rendered URL reader
  placed the function at `:279-287`; raw pinned bytes and the patch hunk
  (`@@ -274,6 +274,9 @@`) put it at `:273-281`. Raw bytes are authoritative.
- **This lab**: extracted C driver whose fault statements are byte-for-byte
  copies of pinned lines under `#line`; 10 PASS / 0 FAIL, ASan `WRITE of size
  1` at `hpack_v4.3.10:277`, chosen `0x5a` and `0xa5` read back byte-exact
  past a 16-byte region, guard-page fault, fixed/benign ASan-clean.

## Source-bound mechanism

Line numbers are from raw pinned bytes, `v4.3.10` unless marked fixed.

1. `hpack.c:1148-1149` selects the `WSI_TOKEN_HTTP_COLON_PATH` header;
   `:1151-1152` calls `lws_parse_urldecode(wsi, &c1)`, producing a byte from
   the attacker-supplied HPACK `:path` value (optionally Huffman-decoded
   earlier in the same function).
2. `:1168` calls `lws_frag_append(wsi, c1)` and returns on a nonzero result.
   Raw `:280` returns true once `pos >= max_http_header_data`, so this real
   caller stops when the arena fills: it cannot supply a chosen byte at
   `pos == limit`. The harness hand-stages that precondition
   (`gen_driver.py:106`, chain mode `:122`); the naive real route is closed
   by the build check below and any other route stays UNKNOWN.
3. `:273-281` is `lws_frag_append`: `:275` fetches `wsi->http.ah`; `:277`
   executes `ah->data[ah->pos++] = (char)c` with no prior bound check;
   `:280` tests `pos >= max_http_header_data` only **after** the store. The
   context setting `max_http_header_data` bounds the separately malloc'd
   `allocated_headers.data`, so a staged `pos == limit` puts the next stored
   byte one past that arena. The post-write check is the consumer detail
   that blocks the naive long-`:path` route.
4. All three real call sites (`:286`, `:744`, `:1168`) check the return, so
   the reachable primitive on the real path is UNKNOWN, not an observed
   chosen byte. The terminating NUL from `lws_frag_end` — raw v4.3.10
   `:283-294`, calling `lws_frag_append(wsi, 0)` at `:286` (`:289` is a
   comment) — was not exercised in the harness; the real-build check below
   did observe NUL stores, still inside the arena. The `:283-295` / `:289`
   call-site numbering belongs to v5.0.0 (`:286-297` / `:289`), not v4.3.10.
5. Fixed `v5.0.0:277-278` rejects `pos >= max_http_header_data` before the
   store; `:280` is the same assignment. The fix patch adds exactly that
   two-line guard plus a blank line and nothing else.

## Lab evidence

`cd lab/frontier/libwebsockets2shell && bash run.sh <outdir>`:

- 10 PASS / 0 FAIL, exit 0. Two independent five-run groups both
  `sha256=45cd97c83c032f5ff9217e568225ea95441df31480495b72cb944d3b3f798833`.
  A clean `git archive HEAD` replay at commit `e6a406d` reproduced 10 PASS /
  0 FAIL, rc 0 and the same digest in a fresh temp directory.
- Rung 1 (chosen byte `0x5a`, limit 16):
  `rv=1 pos=17 oob0=5a oob1=00` — the post-write check fires only after the
  17th byte is stored past a 16-byte arena.
- Rung 2 (faithful caller shape: `0x41` at the last in-bounds slot, then the
  chosen byte): `r1=1 r2=1 pos=17 last=41 oob0=5a oob1=00`, with the next
  slot untouched.
- Rung 3 (ASan, exact 16-byte allocation): `heap-buffer-overflow`, `WRITE of
  size 1`, frame `lws_frag_append` at `hpack_v4.3.10:277` — the verbatim
  pinned assignment.
- Rung 4 (INSTRUMENTED chosen-byte control): `0x5a` at offsets 16, 32 and 48
  (limits 16/32/48), plus an independent `0xa5` run giving `oob0=a5` — the
  value is selected by the harness, not a fixed marker or adjacent heap word.
- Guard page: the first past-end store faults SIGSEGV (rc 139).
- Fixed `v5.0.0`: hostile `collab` returns `rv=1 pos=16 oob0=00` (no store;
  `00` is uninitialized past-end heap, not an installed sentinel); benign
  `inbounds` writes `last=41` normally. Vulnerable benign, fixed hostile and
  fixed benign ASan runs are all clean — counterexamples against an oracle
  that flags every input.
- The harness's 16/32/48 are logical limits; ASan/guard confirm a real
  boundary at exact 16 and 24, not necessarily malloc chunk edges at every
  limit. Since `0xa5` is also the `malloc` fill value, the `0x5a` runs carry
  the chosen-value proof.

## Rung-4 feasibility assessment

The harness primitive is a chosen-byte write at chosen offsets past a bounded
arena (rung 4 INSTRUMENTED). It is not a real-path demonstration: the harness
hand-stages `pos == limit`, allocates the arena alone, and observes neither a
real chunk neighbour nor a pointer nor diverted control flow. The real
consumer check below shows the naive long-`:path` route stops at the boundary.

## Real-build consumer-reality check (2026-11-21, W1, NEGATIVE)

Full source trees were fetched from the pinned tags under
`lab/libwebsockets2shell-src/` (provisioning; never a network probe).
`v4.3.10` was built with `LWS_WITH_ASAN=ON`, ASan+UBSan, Debug and HTTP/2;
TLS was compiled in because `LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE` switches
roles through `lws_role_call_alpn_negotiated`, which compiles out under
`LWS_WITH_SSL=OFF`. `max_http_header_data` was 32. A minimal server
(`lab/libwebsockets2shell/h2server.c`) binds only 127.0.0.1;
`lab/libwebsockets2shell/h2client.py` sends the HTTP/2 preface, an empty
SETTINGS frame and one HEADERS frame whose HPACK literal `:path` (static
index 5) decodes to 65, 201 or 8..200 bytes. Both built `hpack.c` files
hash to the pins in `PROVENANCE.md`.

Observed on v4.3.10 (raw logs in `lab/libwebsockets2shell/evidence/`):

- `http/2 prior knowledge`, `http2: ... established` — the real H2 path ran;
- `lws_hpack_interpret: frag app fail`, `lws_h2_parser: hpack failed`,
  connection closed — the real caller returned at the boundary;
- **no hpack-related ASan report** at any length, including 201 bytes and
  the terminating-NUL limb;
- a gdb breakpoint at raw `hpack.c:277` logged 253 actual stores over nine
  path lengths (8/16/30/31/32/33/64/100/200): every store had `max=32` and
  `pos` in 0..31, including NUL stores at `pos=9,13,18,28,31,...`. No call
  entered the store at `pos >= 32`.
- Source audit of the full v4.3.10 tree: `:277` is the only mutation of
  `ah->pos` in H2, all three call sites (`:286`, `:744`, `:1168`) check the
  post-write return, and `_lws_create_ah` allocates `ah->data` as a separate
  `lws_malloc(data_size)` (`parsers.c:50`) — no live pointer sits inline
  after the arena.

v5.0.0 control (`h2server5r`, recoverable ASan): same `frag app fail` /
`hpack failed`, no hpack ASan. Its startup alone reports an unrelated
`stack-buffer-overflow` in `lws_sa46_parse_numeric_address`
(`network.c:947`) during bind, before any connection;
`-fsanitize-recover=address` kept the control running. That finding is not
CVE-2026-19773.

**Disposition**: for the claimed HPACK `:path` route in a stock v4.3.10
server, a chosen-byte one-past-end write was NOT observed; the post-write
check at `:280` and the caller return close it. Rung 4 real-path stays
UNKNOWN/negative for this route and the harness's INSTRUMENTED grade is
unchanged. Pointer control, control-flow diversion and the advisory's RCE
remain undemonstrated. Other possible routes were not exercised and stay
UNKNOWN.

## Scope and boundaries

Loopback-only local process drivers and a loopback server; no external
probe. Every socket was 127.0.0.1. No real heap neighbour, pointer or
execution claim. Sources were fetched read-only as provisioning. Harness
stand-ins and the exact copied ranges are enumerated in `PROVENANCE.md`.
