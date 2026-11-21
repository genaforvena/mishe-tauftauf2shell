# PROVENANCE — Libwebsockets2Shell (CVE-2026-19773)

All sources below were fetched read-only from public origins on 2026-11-21;
no HTTP/2 traffic, socket or external probe was sent anywhere.

## Upstream pins (SHA-256 of the exact bytes stored in `src/`)

| Artifact | Origin | SHA-256 |
| --- | --- | --- |
| `src/hpack.v4.3.10.c` (affected) | `https://raw.githubusercontent.com/warmcat/libwebsockets/v4.3.10/lib/roles/h2/hpack.c` | `5ce2d424f330fac11735a8c1f9dd50a430c02fb653012f50dd0ae3be69de5439` |
| `src/hpack.v5.0.0.c` (fixed) | `https://raw.githubusercontent.com/warmcat/libwebsockets/v5.0.0/lib/roles/h2/hpack.c` | `9232db68b9b9982a0df02b4e6105993de2d6d93d8a4bb26a070b3c756e8ea584` |
| `src/fix19773.patch` | `https://github.com/warmcat/libwebsockets/commit/824151862f37bc72f46d9a3e01d5b9408d313a0b.patch` | `c8dab8820a000a92122dbf6e8e511973789816a6f9d4207569cd4c890ffd2ba9` |
| `src/cve19773.json` (ZDI CNA record) | `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/19xxx/CVE-2026-19773.json` | `ae98ef58f5912df664ac1fa323ed794a4193f310a33863076cf0114fd014bcc5` |
| `src/zdi-26-590.html` | `https://www.zerodayinitiative.com/advisories/ZDI-26-590/` | `86eed822ed539fd37519909e6045a0dbbfaea8a1b1250e770f74600fecdc56bc` |

`gen_driver.py` re-verifies every pin on every run and exits on drift.
The rendered URL reader reports the `lws_frag_append` function at `:279-287`
(v4.3.10); the raw pinned bytes place it at `:273-281`. All line numbers in
the brief and generator come from the raw bytes and the fix patch hunk
(`@@ -274,6 +274,9 @@`), not from the rendered reader.

## Verbatim pin ranges and the hand-written caller shape

- Affected v4.3.10 `hpack.c:273-281` is copied verbatim: `:275` obtains
  `wsi->http.ah`; `:277` writes `ah->data[ah->pos++] = (char)c` with no prior
  bound; `:280` checks the bound only **after** the write. Fixed v5.0.0
  `hpack.c:273-284` is copied verbatim: `:277-278` rejects
  `ah->pos >= max_http_header_data` before any write; `:280` is the store.
- Caller `v4.3.10:1148-1172` is **hand-written**, not copied: `:1151`
  `lws_parse_urldecode(wsi, &c1)` supplies an attacker-chosen byte for a
  `:path` header; `:1168` calls `lws_frag_append(wsi, c1)` and `:1172`
  returns on a nonzero result. Raw `:280` returns true at `pos == limit`,
  so the real caller cannot supply a chosen byte at that point. All three
  real call sites (`:286`, `:744`, `:1168`) check the return; `:277` is the
  only `pos` mutation. The harness hand-stages `pos == limit`
  (`gen_driver.py:106`, chain mode `:122`). Real-path reachability of a
  chosen-byte OOB remains UNKNOWN.
- The upstream fix patch adds exactly those three guard lines.

## Harness stand-ins, all outside the copied statements

`Vips`-free C stand-ins define `struct allocated_headers` (`data`, `pos`,
`nfrag`, `frags`), `struct lws_context { max_http_header_data }` and the two
`wsi` substructures the copied lines dereference. `malloc(N)` filled with
`0xa5` models an exact allocation; an mmap page ending in `PROT_NONE` places
`data[N]` on the guard page for a fault control. Modes: `collab` (single
hostile store plus readback), `chain` (last in-bounds byte `0x41`, then one
chosen OOB byte, faithful to the caller's early return), `exact`/`exactok`
(ASan hostile/in-bounds with no out-of-range readback), `inbounds`, `guard`.
No libwebsockets build, HPACK frame, HTTP/2 server, socket or allocator
neighbour is exercised.

## Harness digests and replay

- `gen_driver.py` `b98086a1348b35b66985154242dde8a05b200a4b70f339afb38485b4f64a5a5c`
- `run.sh` `6f700295d8506e8d7c483ff80693c50ccffca01afc1a5ef3a563427bb4bde401`
- Generated `driver_vuln.c`
  `11dda4813ea15159ac9730ce37fdbc001f6265ba829d7e48357661307661072e`
- Generated `driver_fixed.c`
  `a3bcc9e45eb331eead1c212767fc2b0834583b0eda5ae8569d5ad4fff5f1fee5`
- `bash lab/frontier/libwebsockets2shell/run.sh <outdir>`: **10 PASS / 0 FAIL,
  ALL CHECKS PASS rc 0**; two independent five-run groups both
  `sha256=45cd97c83c032f5ff9217e568225ea95441df31480495b72cb944d3b3f798833`.
- Clean `git archive HEAD` replay at commit `e6a406d` into
  `/tmp/lws-replay-76K22L`: 10 PASS / 0 FAIL, rc 0, both five-run groups
  `sha256=45cd97c83c032f5ff9217e568225ea95441df31480495b72cb944d3b3f798833`.
  ASan PIDs, addresses and build paths are excluded from the trace digest so
  clean replays are byte-identical.
