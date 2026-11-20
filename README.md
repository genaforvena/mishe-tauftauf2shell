# mishe-tauftauf2shell

A public research lab that tries to take "X2Shell" runtime vulnerabilities
all the way to **rung 4 — demonstrated security impact** — and publishes
every step, including the ones that fail.

It studies ten real vulnerability families in local, isolated copies of
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
  Rung 3 is confirmed under gdb with Stage A chosen-byte placement;
  Stage C (pointer control) remains UNKNOWN, bounded by the observed
  wire-byte alphabet. The earlier bounded race sweep was negative.
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

Nothing here scans the internet or talks to a real target. Sources are
downloaded from their official homes, builds and test servers run on
`127.0.0.1`, and a separate mind re-runs every claimed result before it
is called established.

## What it has achieved so far

| Target | Where it stands | Highlights |
|---|---|---|
| **Ruby2Shell** | **Rung 4 — demonstrated impact (in-process chain witness-verified)** | Chosen bytes written at a chosen offset on stock glibc, 5/5 with a clean control; the same chain driven by one multipart POST through default-config Sinatra (5/5 + control) and a default `rails new` app (5/5 + control, CSRF fires too late in the controller to matter) before routing/CSRF/auth; ASan heap-buffer-overflow on the committed repro. Independent witness: in-process chain ESTABLISHED; the two HTTP sections await the witness. [Full report](reports/ruby2shell-investigation.md) |
| **PHP2Shell** | **Rung 3 — confirmed corruption** | Deterministic OOM-during-request-parsing trigger (rung 1); every cheaply reachable SAPI consumer surveyed with negatives observed, not assumed; rfc1867 upload-progress PoC ported with version-discriminating behavior on affected 8.4.26 vs fixed builds. Reopened 2026-11-20 under CVE-2026-126714: both splice halves reproduced on both pinned ASan builds — an interrupted real session write leaves a replacement prefix plus carrier tail on disk and the next request promotes the object; the kill is shim-simulated, not a remote trigger. The 8.4.28 fix was verified in the lab: under the same kill the write leaves only a truncated new prefix and no promoted object. [Status](reports/php2shell-status.md) |
| **Apache2Root** | **Rung 3 — confirmed corruption with Stage A placement** | Differential child SIGSEGV on affected 2.4.70 and clean fixed control under gdb, with chosen-byte placement at a capacity boundary; the earlier bounded ASan sweep was negative and is preserved. [Report](reports/apache2shell-investigation.md) |
| **Mosquitto2Shell** | **Rung 3 — confirmed corruption** | ASan `WRITE of size 256`, 3 bytes after a 1-byte region, via `net__read_ws (net_ws.c:305)` on affected 2.1.0-2.1.2; clean close on fixed 2.1.3; Stage A places 4N chosen bytes at a chosen offset. Stock-glibc tcache/rung 4 remains UNVERIFIED. [Brief](reports/frontier-mosquitto2shell.md) |
| **Node2Shell** | **Rung 3 — deterministic memory effect** | One-request stock-glibc abort on v20.20.2; deterministic ASan differential v24.22.2 (affected) vs fixed control; a deterministic PREV_INUSE-clear on bare v24.22.2 with controls. [Report](reports/node2shell-investigation.md) |
| **Dragonfly2Shell** | **Rungs 1/2 — established on stock** | A 20000-byte key created over RESP is echoed through memcached in a 20024-byte reply; witness gdb observed `SendValue` with `rdx=0x4e20`. Stock rung 3 and rung 4 are NOT demonstrated; the ASan 20000-byte write is a labeled synthetic harness. [Status](reports/dragonfly2shell-status.md) |
| **Postgres2Shell** | **Rung 3 — confirmed corruption under Valgrind** | FDW batch-insert overcount on stock 17.11: uninitialised 8-byte heap value used as a pointer, invalid write at `0x38`, SIGSEGV; fixed 17.12 completes. It requires `PR:L`, so pre-auth RCE is NOT demonstrated. [Status](reports/postgres2shell-status.md) |
| **Brotli2Shell** | **Rung 3 — confirmed corruption (standalone harness)** | Pinned two-stage stream drives 20 attacker-chosen bytes past an 8-byte decoder buffer into named state fields; fixed build rejects with `ERROR -17`. Rung 4 is NOT demonstrated; network reachability is a claim. [Status](reports/brotli2shell-status.md) |
| **Freeradius2Shell** | **Rung 4 — demonstrated impact in a standalone harness** | A crafted EAP-FAST ticket writes 208 bytes into a 152-byte stack structure and executes a chosen `verify_marker()` address at rc 42; fixed build rejects the same ticket. Live `radiusd` reachability and key-unknown byte control remain UNKNOWN. [Status](reports/freeradius2shell-status.md) |
| **Falkordb2Shell** | **Rung 3 — confirmed corruption (standalone harness)** | A masked zero-payload extended-length frame produces 525 out-of-bounds writes; chosen mask bytes overwrite a canary at chunk offset 104; ASan confirms the heap overflow. Rung 4 is NOT demonstrated because the mask repeats every four bytes. [Status](reports/falkordb2shell-status.md) |

Work is ongoing: PHP's rung-4 placement question (including the reopened
session-splice lane), Node's path from corruption to control, Apache's
path from Stage A placement to Stage C pointer control, Mosquitto's
stock-glibc rung-4 question, Dragonfly's stock rung-3/4 gap, Postgres's
wrong `PR:L` pointer identity, Brotli's pointer fields beyond index 27,
FreeRADIUS's live `radiusd` replay, and FalkorDB's four-byte-repeating
mask are still open. Each is recorded as an UNKNOWN in its status file
rather than papered over. Failed hypotheses and negative results stay
in the reports.

## How the plant works

Each target is its own mind with its own window: **ruby2shell**,
**php2shell**, **node2shell**, **apache2shell** and **mosquitto2shell**
pursue their lane end-to-end — build, harness, debugger, report. Three
further minds cut across them:

- **docs** keeps this README and `docs/` true to the shipped code. It is
  woken by the `repo-change` git-commit signal and owns the
  [reproducibility index](docs/reproducibility.md); it is the net under
  authors, not a routine review gate.
- **witness** re-runs every claim from a clean checkout; the author's
  report is never acceptance.
- **operator** is the owner's delegate. It approves scoped work from a
  recorded list of standing permissions, admits new X2Shell-class targets
  it finds in public advisories, and creates a new mind, window and lab
  lane for each admission. Its first find was Node2Shell.

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
  `mosquitto2shell` and `docs` windows show each mind's wall and wake log;
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
