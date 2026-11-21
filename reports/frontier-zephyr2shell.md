# Frontier brief — Zephyr HTTP/2 static-FS RX-length alias (Zephyr2Shell)

**Status: new frontier find, brief + harness COMPLETE (2026-11-21 ~11:38Z) —
pending independent witness replay and operator admission.** Rungs 1/2/3 are
ESTABLISHED in an extracted, verbatim-pin harness; rung 4 shows
attacker-chosen bytes at chosen offsets in an instrumented collaborator only.
No Zephyr build, HTTP/2 wire traffic, RTOS socket, real
`struct http_client_ctx` layout, adjacent-object metadata, pointer overwrite or
execution was observed — all stay UNKNOWN. The advisory's own claims of a live
ASan abort, control-data overwrite and plausible code execution are **claims to
reproduce**, not results obtained here.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-82391 / GHSA-8jrg-wx88-g75j, CNA Zephyr Project.
  CVE record published `2026-11-10T22:07:39.047Z`, updated 2026-11-13; the
  GitHub advisory HTML page shows `d3zd3z` publishing on 2026-10-26 with an
  embargo to 2026-11-10 — both dates recorded, no claim reconciled beyond the
  pinned records. Title: "Out-of-bounds write in Zephyr HTTP/2 server
  static-filesystem handler via corrupted receive-buffer length". CVSS 3.1
  `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` = **9.1 CRITICAL**, CWE-787.
  Unauthenticated HTTP/2 GET, `CONFIG_HTTP_SERVER_VERSION_2=y` by default,
  `CONFIG_FILE_SYSTEM=y`, one `HTTP_RESOURCE_TYPE_STATIC_FS` resource.
  Pinned verbatim in `lab/frontier/zephyr2shell/src/advisory82391.json`
  (OSV record); the CVE JSON and advisory HTML were read-only cross-checks.
  The `api.github.com/advisories/...` endpoint returned 404; nothing is claimed
  from it.
- **Affected/fixed**: `>=4.0.0 <4.3.2` and `>=4.4.0 <4.5.0`; patched in
  **4.3.2** and **4.5.0** (backports PR #117602 / #117603). Fix commit
  `4e0a5f38b14dba5891fb558c49a526f9f6a3cc29` (PR #117267), introduced by
  `e55278a87be4e5534ba772b23e459882866bcd6d`. Fix patch pinned verbatim in
  `src/fix82391.patch`.
- **Raw sources**: `http_server_http2.c` at tags `v4.4.0` (vulnerable) and
  `v4.5.0` (fixed), `http_server_core.c`, `include/zephyr/net/http/server.h`
  and `subsys/net/lib/http/Kconfig` at `v4.4.0`; all seven pins SHA-256-listed
  in `lab/frontier/zephyr2shell/PROVENANCE.md` and re-verified by
  `gen_driver.py` on every run (exit 3 on drift).
- **This lab**: extracted C driver whose fault statements are byte-for-byte
  copies of pinned lines under `#line`; 10 PASS / 0 FAIL, ASan
  `WRITE of size 1024` at the verbatim `core_v4.4.0:565`, chosen bytes at three
  past-end offsets, guard-page fault, fixed/benign ASan-clean.

## Source-bound mechanism

Line numbers are from `v4.4.0` unless marked fixed.

1. `http_server_http2.c:496` (compression branch) and `:499` (default branch)
   pass `&client->data_len` as the `file_size` out-parameter of
   `http_server_find_file()`. `client->data_len` is the count of unprocessed
   bytes in `client->buffer[HTTP_SERVER_CLIENT_BUFFER_SIZE]` — `server.h:422`
   and `:428`, default **256** (`Kconfig:95,97`).
2. `http_server_core.c:892` writes `*file_size = dirent.size;`, replacing the
   bounded RX residue with the on-disk file size. Nothing restores it.
3. `http_server_http2.c:532` copies the corrupted residue into `remaining`,
   so the send loop consumes the file-size count too.
4. `http_server_core.c:557` continues the request dispatch loop while
   `client->data_len > 0`; with a served file larger than 256 bytes the loop
   keeps parsing beyond the received data.
5. `http_server_core.c:563-566` runs `memmove(client->buffer, client->cursor,
   client->data_len)` — a file-size-byte write into the 256-byte buffer. The
   advisory states the peer controls bytes at `client->cursor` by appending
   data after the request; the harness exercises that as a stand-in.
6. `http_server_core.c:697` then calls `zsock_recv(client->fd,
   client->buffer + client->data_len, sizeof(client->buffer) -
   client->data_len, 0)`. With `data_len > 256` the `size_t` length underflows.
   This second limb is **source-bound only** in this harness; no socket or
   underflowed receive was executed.
7. Fixed `v4.5.0:472` declares a local `size_t file_size`, passes `&file_size`
   at `:497`/`:500`, and uses `remaining = file_size` at `:535`; the RX
   residue stays bounded. The fix patch changes exactly those three lines.

## Lab evidence

`cd lab/frontier/zephyr2shell && bash run.sh <outdir>`:

- 10 PASS / 0 FAIL, exit 0. Two independent five-run groups both
  `sha256=48568d4883dd3ca4125fc0dbb6371aa886fc3e9ed3d7362f778815cd3201f0e0`.
- Rung 1 (hostile 1024-byte served file):
  `alias filesize=1024 data_len=1024 remaining=1024` — the RX residue is the
  file size.
- Rung 2 (seed `0x41`): `oob300=4443424144434241` at offsets 300, 500 and 900
  past the 256-byte buffer, read back byte-exact.
- Rung 3 (ASan, exact allocation): `heap-buffer-overflow`, `WRITE of size
  1024`, `0 bytes after 256-byte region`, fault frame
  `main core_v4.4.0:565` — the verbatim pinned `memmove` line.
- Rung 4 (seed `0x5a`): `oob300=5d5c5b5a5d5c5b5a` at the same three offsets.
- Guard page: first past-end store faults SIGSEGV (rc 139).
- Fixed `v4.5.0`: hostile served file leaves `data_len=64` (the legitimate
  residue) and all OOB readbacks zero; benign 32-byte file accepted; ASan clean
  on hostile and benign. Vulnerable driver on the benign file is ASan-clean —
  a counterexample against oracle false positives.

## Rung-4 feasibility assessment

The primitive is strong: a single unauthenticated HTTP/2 GET overwrites a
length field with a peer-influenced file size and feeds it to a `memmove` and a
`size_t`-underflowing receive. In the lab the **chosen bytes land at chosen
offsets** past a 256-byte region (rung 4 INSTRUMENTED). Moving beyond that is
not established here: the harness allocates the buffer alone with no real
`struct http_client_ctx` neighbours, so no adjacent `current_detail`,
`current_stream`, `parser_settings` function-pointer table or work handler was
overwritten; no pointer value was controlled; no control flow was diverted; no
marker executed. MMU-less Zephyr targets place clients in static memory, whose
adjacency this harness does not model. The advisory's "plausibly control-data
overwrite leading to code execution" stays a claim.

**Cheapest rung-raising experiment**: build the real Zephyr HTTP server for
`native_sim` (or QEMU x86) with `CONFIG_HTTP_SERVER_VERSION_2=y`,
`CONFIG_FILE_SYSTEM=y` with a >256-byte static file, and an ASan-instrumented
build; drive the documented HTTP/2 preface + HEADERS GET over loopback with a
pipelined PING frame. Observe the `memmove` at the pinned line and the
underflowed `zsock_recv`. That needs a Zephyr toolchain and a real daemon,
deliberately out of this extracted-driver lane; it is the right first task for
a dedicated target mind after admission.

## Scope and boundaries

Loopback-only local process drivers; no external probes. No Zephyr source tree
was built or run, no socket was opened, no stock allocator neighbour, real
client struct, RTOS memory map, pointer or execution claim. Sources were
fetched read-only as provisioning. Harness stand-ins and copied ranges are
enumerated in `PROVENANCE.md`.
