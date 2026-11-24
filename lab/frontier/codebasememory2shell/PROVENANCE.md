# codebasememory2shell — laboratory provenance

## Candidate

CVE-2026-114494 / GHSA-vpgh-g3jg-ggx9, "codebase-memory-mcp: Stack
out-of-bounds write in query_graph via a RETURN or WITH clause with more than
32 items". CNA GitHub, Inc.; published 2026-11-20; HIGH 7.8
`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`; CWE-121 and CWE-787;
DeusData codebase-memory-mcp affected `< 0.9.0`, fixed `0.9.0`.
<https://www.cve.org/CVERecord?id=CVE-2026-114494>
<https://github.com/DeusData/codebase-memory-mcp/security/advisories/GHSA-vpgh-g3jg-ggx9>

The advisory claims: unbounded projection count in RETURN/WITH; fixed
32-element stack arrays in the executors; single `query_graph` tool argument;
reliable server crash and potential confidentiality/integrity compromise;
also an uninitialized-stack-read path in result-column construction.
All of that is a **claim** until the lab measurements below.

## Provisioning (read-only public fetches, no external probes)

- Vulnerable tree: commit `5554f8a46abf` (parent of the fix), fetched as
  `pins/5554f8a46abf.tar.gz` from
  `https://codeload.github.com/DeusData/codebase-memory-mcp/tar.gz/5554f8a46abf`
  and extracted under `src/codebase-memory-mcp-5554f8a46abf/`.
- Fixed tree: commit `e69e0844dbc1c737ebd3d17e97007d0f5cf16beb`
  ("cypher: bound RETURN/WITH projection width to the result column limit",
  authored 2026-07-07, 2 files +60/-4), fetched as
  `pins/e69e0844dbc1c737ebd3d17e97007d0f5cf16beb.tar.gz` and extracted under
  `src/codebase-memory-mcp-e69e0844dbc1c737ebd3d17e97007d0f5cf16beb/`.
- Fix diff read at
  <https://github.com/DeusData/codebase-memory-mcp/commit/e69e0844dbc1c737ebd3d17e97007d0f5cf16beb>.
  It adds, in `parse_return_or_with()` after the comma loop:
  `if (r->count > CBM_SZ_32) { free(r->items); free(r); return CBM_NOT_FOUND; }`
  and a fork-isolated 48-column RETURN regression test in `tests/test_cypher.c`.
- Pin hashes: `PINS.sha256`. No source outside these two commits is used by
  the harness.

## Harness

`harness.c` is the only lab-authored C file. It calls the pinned, unmodified
`cbm_cypher_execute()` with an in-memory `cbm_store_t`, one `Function` node
whose `name` is a 63-byte chosen pattern, and an N-item `RETURN`/`WITH`
projection of `f.name`. N is an argument, so the same binary serves the
in-bounds control (32), the first out-of-bounds case (33) and larger cases.

`build.sh` compiles the project's own `src/cypher/cypher.c`, `src/store/store.c`,
20 foundation modules and vendored sqlite3/yyjson, plus vendored mimalloc and
tree-sitter runtime objects compiled with the flags used by the project's
`Makefile.cbm` test build. Three binaries: `harness-vuln-asan`,
`harness-fixed-asan`, `harness-vuln-plain` (no sanitizer, for byte-level gdb).

All execution is local: no socket, no server, no off-loopback probe.
