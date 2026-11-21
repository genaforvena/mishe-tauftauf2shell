# Frontier brief — libwebsockets HTTP/2 HPACK path OOB write (Libwebsockets2Shell)

**Status: new frontier find, brief + harness COMPLETE (2026-11-21 ~12:20Z) —
pending independent witness replay and operator admission.** Rungs 1/2/3 are
ESTABLISHED in an extracted, verbatim-pin harness; rung 4 shows
attacker-chosen wire-derived bytes at chosen offsets just past a bounded
header arena in an instrumented collaborator only. No HPACK frame, HTTP/2
server, socket, real heap neighbour, pointer, control-flow diversion or
execution was observed — all stay UNKNOWN. The advisory's "execute arbitrary
code" is a claim to reproduce, not a result obtained here.

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
  `gen_driver.py` on every run (exit 2 on drift). The rendered URL reader
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
   The chosen value therefore reaches the store in the very next step.
3. `:273-281` is `lws_frag_append`: `:275` fetches `wsi->http.ah`; `:277`
   executes `ah->data[ah->pos++] = (char)c` with no prior bound check;
   `:280` tests `pos >= max_http_header_data` only **after** the store. The
   context setting `max_http_header_data` bounds the allocated
   `allocated_headers.data`, so a long decoded `:path` drives `pos` to the
   allocation end and the next byte lands one past it.
4. Because the caller returns immediately when `:280` becomes true, the
   reachable primitive in this path is a **single chosen byte** just past the
   arena. A possible terminating NUL from `lws_frag_end` (`:283-295`, which
   calls `lws_frag_append(wsi, 0)` at `:289`) was not exercised and stays
   UNKNOWN.
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
- Fixed `v5.0.0`: hostile `collab` returns `rv=1 pos=16 oob0=00` (no store,
  sentinel-region byte intact); benign `inbounds` writes `last=41` normally.
  Vulnerable benign, fixed hostile and fixed benign ASan runs are all clean —
  counterexamples against an oracle that flags every input.

## Rung-4 feasibility assessment

The primitive is a chosen-byte write: an unauthenticated HPACK-decoded `:path`
byte supplies both value and arrival, and the landmark is a bounded
`allocated_headers.data` arena. In the lab the **chosen byte lands at chosen
offsets** past that arena (rung 4 INSTRUMENTED). Beyond that nothing is
established: the harness allocates the arena alone in `exact`, `collab` or
guard-page layouts, so no real chunk metadata, adjacent object, pointer or
function pointer was overwritten; no control flow was diverted; no marker
executed. The caller's early return limits this path to one past-end byte;
whether libwebsockets' header-arena allocator places a live pointer in the
following byte is UNKNOWN. Whether a stock v4.3.10 server reaches this decoder
over an unauthenticated HTTP/2 connection is an advisory claim, not an
observed local path.

**Cheapest rung-raising experiment**: build libwebsockets at tag `v4.3.10`
with `LWS_ROLE_H2` and ASan, set `max_http_header_data` to 32, start a server
bound only to 127.0.0.1, and send one HEADERS frame whose decoded `:path`
exceeds 32 bytes; expect the `WRITE of size 1` at pinned `:277`. Then freeze
the first past-end byte with a chosen marker and inspect the adjacent
allocation under gdb before claiming pointer control. That work belongs to a
dedicated target mind after admission, not this extracted-driver lane.

## Scope and boundaries

Loopback-only local process drivers; no HPACK frame, HTTP/2 connection or
external probe. No libwebsockets source tree was built or run, no socket was
opened, no stock allocator neighbour, real frame, transport, pointer or
execution claim. Sources were fetched read-only as provisioning. Harness
stand-ins and the exact copied ranges are enumerated in `PROVENANCE.md`.
