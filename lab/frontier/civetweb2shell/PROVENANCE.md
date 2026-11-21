# CivetWeb CVE-2025-55763 — artifact provenance

All network fetches below were provisioning (public advisories and source
tarballs). Every experiment ran against 127.0.0.1 listeners this lab started;
no external target was probed.

## Pins (committed, offline replayable)

| file | source | sha256 |
|---|---|---|
| `pins/civetweb-1.16.tar.gz` | `https://codeload.github.com/civetweb/civetweb/tar.gz/refs/tags/v1.16` | `f0e471c1bf4e7804a6cfb41ea9d13e7d623b2bcc7bc1e2a4dd54951a24d60285` |
| `pins/civetweb-fixed-c584455.tar.gz` | `https://codeload.github.com/civetweb/civetweb/tar.gz/c584455624d9a9f6ec72839f61dd3cdb9d8435ba` | `7e3ba593fe46de4ebfcdea92977860cd530481d9650722681812a8afdfd78864` |
| `pins/civetweb-fixed-c584455.patch` | `https://github.com/civetweb/civetweb/commit/c584455624d9a9f6ec72839f61dd3cdb9d8435ba.patch` | `16902ca3d94a2be78c20e982278f9773fe6cc88993e1933afb15e06667998e60` |
| `pins/http_request_crash_input.txt` | `https://raw.githubusercontent.com/krispybyte/CVE-2025-55763/main/http_request_crash_input.txt` | `e8b30b946e41e1ed5b764a10b9ca9c0a9bccc0b0ae8fde2cf02197a0390d91c1` |

Advisory records read: MITRE CVE API
`https://cveawg.mitre.org/api/cve/CVE-2025-55763`; GitHub commit API
`https://api.github.com/repos/civetweb/civetweb/commits/c584455624d9a9f6ec72839f61dd3cdb9d8435ba`
(verified signature, merged 2025-09-02T14:50:01Z); PoC README at
`https://raw.githubusercontent.com/krispybyte/CVE-2025-55763/main/README.md`.
Two transient HTTP 503 responses during download were retried successfully;
no pin was substituted.

## Build

Both trees built offline from the committed tarballs:
`make TEST_ASAN=1 NO_SSL=1 -j4 civetweb` (clang, `-fsanitize=address`, `-g`,
`-DNO_SSL`). The `NO_SSL` flag removes TLS only; the HTTP request path under
test is unchanged. The Makefile's own `TEST_ASAN` target was used rather than
a hand-rolled compiler command.

## Trigger

`GET /` + 9000 `/` + `d?q=1 HTTP/1.1` (9059 bytes). The slash run collapses
under `remove_dot_segments` (`:8069–8218`) to `/d`, an existing directory in
the harness document root, so `handle_request` enters the directory-redirect
branch while the raw request URI remains 9002 bytes long.

## Diagnostic copy

`out-first/instr/` is a **throwaway instrumented copy** of v1.16 (pinned tree
untouched) used once to measure sink lengths: `buflen=17194 link=0 q=9000
requri=2 local=2` for the long-query/short-path request, which proved that
`:15251` budgets the query and cannot overflow. It is not part of the replay
and should not be treated as an artifact.

## Replay

`bash run.sh OUTDIR` rebuilds both pinned trees, sends the crafted request to
three loopback listeners (vulnerable, fixed, short-path negative control), and
emits `OUTDIR/trace.txt` with a normalized sha256. Two runs on 2026-11-21 gave
23 PASS / 0 FAIL and trace sha256
`2ecaac759e4230f9549507091cff212adb68dd63e650d3abf6ced2406e5e2d50`.
ASan PIDs, addresses and host paths are excluded from the trace so replays are
byte-identical.
