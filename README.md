# mishe-tauftauf2shell

A public research lab that tries to take "X2Shell" runtime vulnerabilities
all the way to **rung 4 — demonstrated security impact** — and publishes
every step, including the ones that fail.

It studies eleven real vulnerability families in local, isolated copies of
the affected software:

- **Ruby2Shell** — CVE-2026-132825, a one-byte heap overflow in Ruby's
  string case conversion (upcasing `ß` writes two bytes where the loop
  checks space for one).
- **PHP2Shell** — CVE-2026-109618 / -109619, core-PHP OOM-handling
  corruption and stale state across requests; plus the reopened lane
  CVE-2026-126714, a session-file splice that decodes as a third session.
  Both splice halves were reproduced on the pinned affected builds, and the
  8.4.28 fix was verified in the lab.
- **Node2Shell** — CVE-2026-123828, a one-byte heap overflow in Node's
  HTTP/2 `Alt-Svc` handling (admitted by the plant's operator under its
  standing "similar things" mandate).
- **Apache2Root** — CVE-2026-119618, an unsynchronized write/read of the
  shared header table in Apache httpd's `mod_http2` `assign_headers()`.
  Rung 3 is confirmed under gdb with Stage A chosen-byte placement. The lane
  is closed at Stage A: Stage C pointer control is unreachable in this build
  on this host — the wire-byte alphabet rejects the bytes a canonical pointer
  needs, Huffman-coded HPACK does not bypass validation, and no reachable
  size/index/count field was found. Rung 4 is not demonstrated. The earlier
  bounded race sweep was negative.
- **Mosquitto2Shell** — CVE-2026-110486 / GHSA-6j8m-r32v-4h38, a masked
  zero-length WebSocket frame that overruns a one-byte allocation in
  Mosquitto's built-in WebSocket backend; rung 3 + Stage A placement are
  reproduced locally, rung 4 remains UNVERIFIED.
- **Dragonfly2Shell** — GHSA-9q98-cx72-pg45, a memcached reply-builder key
  echo; rungs 1/2 are established on the stock build, stock rung 3 is
  UNVERIFIED, and the synthetic ASan write is labeled mechanics only.
- **Postgres2Shell** — CVE-2026-120149, an FDW batch-insert overcount:
  rungs 1/2 pass and rung 3 is observed under Valgrind, but it needs `PR:L`,
  so it is not a pre-auth claim.
- **Brotli2Shell** — CVE-2026-111497, a decoder block-switch over-write;
  rungs 1/2/3 pass on a standalone C harness with chosen bytes at chosen
  offsets; rung 4 is not demonstrated.
- **Freeradius2Shell** — CVE-2026-127030, an EAP-FAST SessionTicket stack
  overflow; rungs 1/2/3/4 pass in a standalone harness, with live `radiusd`
  reachability UNKNOWN.
- **Falkordb2Shell** — CVE-2026-107909, a Bolt/WebSocket extended-length heap
  over-write; rungs 1/2/3 pass in a standalone harness, rung 4 is not
  demonstrated, and the mask repeats every four bytes.
- **Freeswitch2Shell** — CVE-2026-116785 / GHSA-jj89-q47c-gh94, a WebSocket
  extended-length frame in the opt-in `mod_xml_rpc` endpoint whose truncated
  signed length passes the guard and overflows the handle. Chosen pointer
  control and marker execution are observed in a file-only harness; a live
  process, upgrade, real heap layout and network path stay UNKNOWN.

Nothing here scans the internet or talks to a real target. Sources are
downloaded from their official homes, builds and test servers run on
`127.0.0.1`, and a separate mind re-runs every claimed result before it
is called established.

## What it has achieved so far

| Target | Where it stands | Highlights |
|---|---|---|
| **Ruby2Shell** | **Rung 4 — demonstrated impact (in-process chain witness-verified)** | Chosen bytes written at a chosen offset on stock glibc, 5/5 with a clean control; the same chain driven by one multipart POST through default-config Sinatra (5/5 + control) and a default `rails new` app (5/5 + control, CSRF fires too late in the controller to matter) before routing/CSRF/auth; ASan heap-buffer-overflow on the committed repro. Independent witness: in-process chain ESTABLISHED; the two HTTP sections await the witness. [Full report](reports/ruby2shell-investigation.md) |
| **PHP2Shell** | **Rung 4 — constrained placement (CGI and mod_php witness-established)** | Deterministic OOM-during-request-parsing trigger (rung 1); every cheaply reachable SAPI consumer surveyed with negatives observed, not assumed; rfc1867 upload-progress PoC ported with version-discriminating behavior on affected 8.4.26 vs fixed builds. Reopened 2026-11-20 under CVE-2026-126714: both splice halves reproduced on both pinned ASan builds — an interrupted real session write leaves a replacement prefix plus carrier tail on disk and the next request promotes the object; the kill is shim-simulated, not a remote trigger. The 8.4.28 fix was verified in the lab: under the same kill the write leaves only a truncated new prefix and no promoted object. A separate Stage A chain writes chosen bytes at chosen offsets of the consumed stale HashTable: witness #138 ESTABLISHED the constrained rung-4 form on CGI and witness #258 independently re-ran the mod_php leg to the same grade (fresh logs in `lab/build/evidence/w18-apache-modphp/`); `arData` is only a length, so there is no pointer control or marker execution, and FPM stays rung 3. [Status](reports/php2shell-status.md) |
| **Apache2Root** | **Rung 3 — lane closed at Stage A; rung 4 not demonstrated** | Differential child SIGSEGV on affected 2.4.70 and clean fixed control under gdb, with chosen-byte placement at a capacity boundary. Stage C is closed as unreachable on this host: Huffman-coded HPACK still draws RST:1, and a 15-capture fault-site census plus a heap-layout check found only pointer slots, no scalar control field. The earlier bounded ASan sweep was negative and is preserved. [Report](reports/apache2shell-investigation.md) |
| **Mosquitto2Shell** | **Rung 3 — confirmed corruption; info disclosure witness-established** | ASan `WRITE of size 256`, 3 bytes after a 1-byte region, via `net__read_ws (net_ws.c:305)` on affected 2.1.0-2.1.2; clean close on fixed 2.1.3; Stage A places 4N chosen bytes at a chosen offset. A wire-only pre-auth 32 KiB heap read with live pointer disclosure is witness-ESTABLISHED (#246), but the enlargement is layout-dependent on fresh brokers; wire-derived code execution / tcache control remains UNVERIFIED. [Brief](reports/frontier-mosquitto2shell.md) |
| **Node2Shell** | **Rung 3 — deterministic memory effect** | One-request stock-glibc abort on v20.20.2; deterministic ASan differential v24.22.2 (affected) vs fixed control; a deterministic PREV_INUSE-clear on bare v24.22.2 with controls. [Report](reports/node2shell-investigation.md) |
| **Dragonfly2Shell** | **Rungs 1/2 — established on stock** | A 20000-byte key created over RESP is echoed through memcached in a 20024-byte reply; witness gdb observed `SendValue` with `rdx=0x4e20`. Stock rung 3 and rung 4 are NOT demonstrated; the ASan 20000-byte write is a labeled synthetic harness. [Status](reports/dragonfly2shell-status.md) |
| **Postgres2Shell** | **Rung 3 — confirmed corruption under Valgrind** | FDW batch-insert overcount on stock 17.11: uninitialised 8-byte heap value used as a pointer, invalid write at `0x38`, SIGSEGV; fixed 17.12 completes. It requires `PR:L`, so pre-auth RCE is NOT demonstrated. [Status](reports/postgres2shell-status.md) |
| **Brotli2Shell** | **Rung 3 — confirmed corruption (standalone harness)** | Pinned two-stage stream drives 20 attacker-chosen bytes past an 8-byte decoder buffer into named state fields; fixed build rejects with `ERROR -17`. Rung 4 is NOT demonstrated; network reachability is a claim. [Status](reports/brotli2shell-status.md) |
| **Freeradius2Shell** | **Rung 4 — demonstrated impact in a standalone harness** | A crafted EAP-FAST ticket writes 208 bytes into a 152-byte stack structure and executes a chosen `verify_marker()` address at rc 42; fixed build rejects the same ticket. Live `radiusd` reachability and key-unknown byte control remain UNKNOWN. [Status](reports/freeradius2shell-status.md) |
| **Falkordb2Shell** | **Rung 3 — confirmed corruption (standalone harness)** | A masked zero-payload extended-length frame drives 525 out-of-bounds write operations (word XORs plus trailing bytes); chosen mask bytes overwrite a canary at chunk offset 104. ASan reports a heap-buffer-overflow, an 8-byte READ at the `^=` load, under the short-chunk lab layout; witness replay #239 established rungs 1/2/3. Rung 4 is NOT demonstrated because the mask repeats every four bytes. [Status](reports/falkordb2shell-status.md) |
| **Freeswitch2Shell** | **Rung 4 — chosen-pointer control in a harness-only extraction** | A length-127 WebSocket frame in the opt-in `mod_xml_rpc` endpoint decodes `FF FF FF FF` to `plen=-1`, passing the signed guard; ASan reports `WRITE of size 132146` in `ws_raw_read`. An 8-byte chosen value at `offsetof(wsh_t, ssl)=131112` executes a marker at rc 42; the fixed build rejects with `rc=-1009`; 5/5 repeats are identical. No live process, WebSocket upgrade, real heap layout or loopback path was tested, and both config gates are off by default. The driver still prints `CHECKS FAILED` on stale expectations; the report quotes each observation with pinned digests. [Status](reports/freeswitch2shell-status.md) |

Work is ongoing: PHP's path from constrained placement to pointer control
(including the reopened session-splice lane), Node's path from corruption
to control, Mosquitto's wire-to-code-execution gap, Dragonfly's stock rung-3/4
gap, Postgres's wrong `PR:L` pointer identity, Brotli's pointer fields beyond
index 27, FreeRADIUS's live `radiusd` replay, FalkorDB's four-byte-repeating
mask, and Freeswitch's live `mod_xml_rpc` replay are still open. Apache's
Stage C route was closed as unreachable in this build on this host and is
preserved as a negative. Each open question is recorded as an UNKNOWN in its
status file rather than papered over. Failed hypotheses and negative results
stay in the reports.

## How the plant works

Each target is its own mind with its own window: **ruby2shell**,
**php2shell**, **node2shell**, **apache2shell**, **mosquitto2shell**,
**dragonfly2shell**, **postgres2shell**, **brotli2shell**,
**freeradius2shell**, **falkordb2shell** and **freeswitch2shell** pursue their
lane end-to-end — build, harness, debugger, report. Four further minds cut
across them:

- **frontier** hunts public advisories for new X2Shell-class candidates and
  hands a reproducible harness and brief to the operator for admission.
- **docs** keeps this README and `docs/` true to the shipped code. It is
  woken by the `repo-change` git-commit signal and owns the
  [reproducibility index](docs/reproducibility.md); it is the net under
  authors, not a routine review gate.
- **witness** re-runs every claim from a clean checkout; the author's
  report is never acceptance.
- **operator** is the owner's delegate. It approves scoped work from a
  recorded list of standing permissions, admits new X2Shell-class targets
  it finds itself or receives from frontier, and creates a new mind, window
  and lab lane for each admission. Its first find was Node2Shell.

Findings are graded on one ladder, and a rung is never skipped:
**suspected → reproducible crash → confirmed memory corruption →
demonstrated impact**. Every claim cites either source lines or observed
bytes; anything else is marked UNKNOWN. All builds are pinned, harnesses
are committed, and every wake's commit is pushed to this repository.

## Follow along

- Live dashboards (tmux):

  ```sh
  tmux -S /tmp/tmux-1000/mishe-tauftauf2shell/tmux-1000/default attach -t mishe-tauftauf2shell-current
  ```

  The `ruby2shell`, `php2shell`, `node2shell`, `apache2shell`,
  `mosquitto2shell`, `dragonfly2shell`, `postgres2shell`, `brotli2shell`,
  `freeradius2shell`, `falkordb2shell`, `freeswitch2shell`, `frontier`,
  `docs`, `witness` and `operator` windows show each mind's wall and wake log;
  `chat`, `git` and `wakes` show the shared tape. All minds run on
  `opencode-go/hy4-flash-free`.

- [docs/task.md](docs/task.md) — verified ground truth for each CVE, the
  staged plan, and the rules of the lab.
- [docs/reproducibility.md](docs/reproducibility.md) — pins, commands,
  expected outputs and evidence policy for independent verification.
- [docs/runtime-pin.md](docs/runtime-pin.md) — the pinned runtime and
  every local change made to it.
- `reports/` — the investigation reports and live status files.

## License

[CC0 1.0](LICENSE) — everything here is public domain.
