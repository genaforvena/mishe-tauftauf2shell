# Provenance — zephyr2shell (CVE-2026-82391 / GHSA-8jrg-wx88-g75j)

All bytes below were fetched read-only from upstream on 2026-11-21. No probe
contacted any external system; fetching sources and advisories is provisioning.
`gen_driver.py` SHA-256 verifies **every one of the seven pins** on each run and
exits 3 with `PIN DRIFT` before rewriting either driver if any byte changes.

| Pin | Source URL | SHA-256 |
| --- | --- | --- |
| `src/http_server_http2.v4.4.0.c` (affected) | `https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v4.4.0/subsys/net/lib/http/http_server_http2.c` | `35c7a3bf7d49c4067314743da2513e05fc545735a98c3954496fb02ff4cdd8bb` |
| `src/http_server_http2.v4.5.0.c` (fixed) | `https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v4.5.0/subsys/net/lib/http/http_server_http2.c` | `578c7c3f13a4e58d34878c8624c02426e7574034a2d06736a091b3b85d5f0a17` |
| `src/http_server_core.v4.4.0.c` (consumer) | `https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v4.4.0/subsys/net/lib/http/http_server_core.c` | `f400c11413db8c13674fca64ab4ccc1fbac9749ec3504e46d7f4ed52c33d988f` |
| `src/server.v4.4.0.h` (struct layout) | `https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v4.4.0/include/zephyr/net/http/server.h` | `43c0522dca2c9acd1a3629a9a15095011c6b989de953bcced9960b3e3691f698` |
| `src/Kconfig.v4.4.0` (buffer default) | `https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/v4.4.0/subsys/net/lib/http/Kconfig` | `173606987989e589faa7b70aaa97fdefafa855c888413cd60fcda1a24bf7bdaf` |
| `src/fix82391.patch` | `https://github.com/zephyrproject-rtos/zephyr/commit/4e0a5f38b14dba5891fb558c49a526f9f6a3cc29.patch` | `65d08ea863c3828411eefc58465443aa5a8afdf8b8ba78764fef6763b3c6477c` |
| `src/advisory82391.json` | `https://api.osv.dev/v1/vulns/CVE-2026-82391` | `3a7928972afd9d25edaea9e7caa91c7e8e20b0c470556b05f47ed095b95401e5` |

Cross-checks (read-only): CVE record `https://cveawg.mitre.org/api/cve/CVE-2026-82391`
(CNA zephyr, CVSS 3.1 9.1, CWE-787, affected 4.0.0–<4.3.2 and 4.4.0–<4.5.0);
GitHub advisory page `https://github.com/zephyrproject-rtos/zephyr/security/advisories/GHSA-8jrg-wx88-g75j`
(fix PR #117267, backports #117602/#117603, introduced by commit
`e55278a87be4e5534ba772b23e459882866bcd6d`). The GitHub advisories API
(`api.github.com/advisories/GHSA-8jrg-wx88-g75j`) returned 404 at fetch time;
the advisory HTML page and both OSV/CVE records are pinned instead.

## Verbatim source statements copied by `gen_driver.py`

Every line under a `#line` marker is copied byte-for-byte from its pin at its
true line number. The generator asserts all pin hashes first; copied ranges:

- Vulnerable driver: `http_server_http2.v4.4.0.c:494-500` (the
  `http_server_find_file(fname, sizeof(fname), &client->data_len, ...)` alias,
  under the `#ifdef` pair) and `:532` (`remaining = client->data_len;`).
- Fixed driver: `http_server_http2.v4.5.0.c:495-501` (local `&file_size`) and
  `:535` (`remaining = file_size;`).
- Both drivers: `http_server_core.v4.4.0.c:557` (dispatch loop
  `while (ret >= 0 && client->data_len > 0);`), `:563-566`
  (`if (client->data_len > 0) { ... memmove(client->buffer, client->cursor,
  client->data_len); }`) and `:892-893` (`*file_size = dirent.size; return ret;`).

`gcc -O0 -g` attributes the ASan fault frame to `core_v4.4.0:565`, the exact
pinned `memmove` line. `server.v4.4.0.h:422/428` and `Kconfig.v4.4.0:95,97`
are source-bound only (256-byte buffer, `size_t data_len`); the driver's
stand-in struct mirrors those two fields and never pretends to reproduce the
full Zephyr layout.

## Harness stand-ins (not upstream code)

`http_client_ctx` is a local stand-in with a pointer-valued `buffer`, `cursor`,
`data_len` and adjacent tail; `http_server_find_file()` is a stand-in whose only
load-bearing statement is the copied `*file_size = dirent.size;`. Three memory
layouts are used: `exact` (256-byte `malloc`, for ASan), `guard` (buf placed so
its last byte touches a `PROT_NONE` page), `collab` (4096-byte zeroed arena
whose bytes 300/500/900 are read back after the copy). The harness supplies no
Zephyr build, HTTP/2 frame parser, RTOS socket, real `struct http_client_ctx`
layout, function-pointer table or control-flow diversion. Peer-controlled bytes
at `cursor` stand in for bytes the advisory says the client appends after its
request; their placement is an instrumented stand-in, not an observed wire path.

## Independent replays

Frontier replay from a clean `git archive HEAD lab/frontier/zephyr2shell`
extraction at commit `0ccfdba` (2026-11-21 ~11:37Z) into `/tmp/z2archive`,
with a separate output directory `/tmp/z2arc-out`: 10 PASS / 0 FAIL, rc 0,
both five-run groups `sha256=48568d4883dd3ca4125fc0dbb6371aa886fc3e9ed3d7362f778815cd3201f0e0`.
All seven pins matched and copied lines were byte-exact. Witness replay
requested in chat #839; author replay is not acceptance.
