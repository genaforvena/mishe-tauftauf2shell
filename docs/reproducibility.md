# Independent verification and reproducibility

This repository is designed so a reader can re-derive every published result
from the recorded sources, commands and expected bytes. First-party scripts
and reports are tracked. Upstream source tarballs, checked-out source trees,
build outputs, compiled `.so`/binaries and raw logs are intentionally
gitignored: they are large or machine-specific, and the commands below
regenerate them. No claim relies on a gitignored file being present in a
fresh checkout.

## Evidence ladder and isolation

Rungs: **suspected** (source/advisory) → **reproducible crash** →
**confirmed memory corruption** → **demonstrated impact**. A negative result
stays in the report. Nothing in this lab contacts a public target; provisioning
downloads public sources, and all triggers run on `127.0.0.1` or inside local
containers whose host ports bind only to loopback.

## Common setup

- Linux x86-64 host, `gcc`/`clang`, `cmake`, `python3`, `curl`, `sha256sum`,
  `gdb`, optionally `valgrind`, `docker` for the container lanes.
- Run all commands from the repository root unless a lane says otherwise.
- Verify any fetched input before building; every script below either pins a
  SHA-256 or records why no published checksum exists.

## Lane index

| Lane | Report | Provision | Build | Replay |
|---|---|---|---|---|
| Ruby2Shell | [report](../reports/ruby2shell-investigation.md) | `bash lab/ruby2shell/provision.sh` | Ruby build recipe in report | `lab/repro/ruby2shell-rung1.rb`, `stageA.rb`, `stageC.sh`, `stageB-http.sh` |
| PHP2Shell | [report](../reports/php2shell-investigation.md), [status](../reports/php2shell-status.md) | `bash lab/php2shell/provision.sh` | `bash lab/php2shell/build.sh`, `build-fpm.sh`, `build-apache.sh`, `build-apache-plain.sh` | `lab/repro/php2shell-*.sh`, `*.py`, `*.gdb` |
| Node2Shell | [report](../reports/node2shell-investigation.md) | `bash lab/node2shell/provision.sh` | prebuilt binaries, no local source build | `sh lab/repro/node2shell-stageA.sh 5`; `lab/repro/node2shell-shrinkwalk/run-multi.sh` |
| Apache2Root | [report](../reports/apache2shell-investigation.md) | `lab/src/httpd-2.4.{70,71}.tar.bz2` + `.sha256` sidecars; `nghttp2-1.64.0.tar.xz` SHA-256 `88bb94c9…dd9` | `lab/frontier/apache2root/build.sh` | `oracle.sh`, `race.sh`, `lab/apache2shell/{sweep,gdb-inspect,drive.py,alphabet-probe.py,huffman-probe.py}`; the Huffman probe now self-checks its wire bytes and was repaired and re-run at 19:11Z (the older Huffman rows were literal restatements) |
| Mosquitto2Shell | [report](../reports/frontier-mosquitto2shell.md), [status](../reports/mosquitto2shell-status.md) | `bash lab/frontier/mosquitto2shell/provision.sh`, `bash …/provision-cjson.sh` | `build.sh`, `build-glibc.sh` | `run.sh`, `placement.sh`, `tcache_probe.py`, `pong_leak_probe.py` |
| Brotli2Shell | [report](../reports/frontier-brotli2shell.md) | `bash lab/frontier/brotli2shell/run.sh` fetches `poc.py` and verifies its SHA-256 | same script builds v1.2.0/v1.2.1/instrumented | same script writes `logs/` and prints digests |
| Postgres2Shell | [report](../reports/frontier-postgres2shell.md) | image digests pinned in `run.sh` | container images by digest | `./run.sh 17.11` and `./run.sh 17.12`; `trigger-vg.sql` for Valgrind |
| Dragonfly2Shell | [report](../reports/frontier-dragonfly2shell.md) | image digests pinned in `run.sh` | container images by digest | `./run.sh v1.40.1`, `./run.sh v1.40.2`; witness files in `lab/witness/dragonfly2shell/` |
| FreeRADIUS2Shell | [report](../reports/frontier-freeradius2shell.md), [status](../reports/freeradius2shell-status.md) | source at vulnerable parent `3f802d74deef`, fix `064567a08f3b`; artifact digests in report | `cd lab/frontier/freeradius2shell && bash run.sh` builds vulnerable/fixed/canary/asan | same script prints `ALL CHECKS PASS`, writes `logs/` and `logs/digests.txt` |
| Falkordb2Shell | [report](../reports/frontier-falkordb2shell.md), [status](../reports/falkordb2shell-status.md) | source at vulnerable parent `40780e992ecc`, fix `0b11a00b34b2` (removes Bolt/WebSocket; lab `FIXED` is a local length guard) | `cd lab/frontier/falkordb2shell && bash run.sh` builds vuln/fixed/asan | same script prints `ALL CHECKS PASS`: `payload_len=4144`, 525 OOB write operations, canary `K:K`, ASan heap-buffer-overflow (READ of size 8 at the `^=` load) |
| Freeswitch2Shell | [report](../reports/frontier-freeswitch2shell.md), [status](../reports/freeswitch2shell-status.md) | source at vulnerable parent `fbac12b451a1`, fix `d557ca6d29e6da4f10824dc158100906a592b91a`; both `mod_xml_rpc` and `enable-websocket` off by default | `cd lab/frontier/freeswitch2shell && bash run.sh` builds vuln/fixed/asan | repaired driver prints `ALL CHECKS PASS` (rc 0) with pinned sources `ws_overflow.c` `75433b5d…` / `run.sh` `637cfa36…`: ASan `WRITE of size 132146` in `ws_raw_read`, 1464 OOB writes from 65536 to 66999, chosen 8 bytes at `offsetof(wsh_t, ssl)=131112` with `marker_called=1` and `rc=42`, fixed `rc=-1009`, 5/5 identical. Harness only; no live process, upgrade, real heap layout or loopback path. |
| Freerdp2Shell | [report](../reports/frontier-freerdp2shell.md), [status](../reports/freerdp2shell-status.md) | source at vulnerable parent `8ec6d3923b`, fix `bf217a5` (3.32.1, `/ 4` division guard); digests `d0a31487…` / `c5186500…` | `cd lab/frontier/freerdp2shell && bash run.sh` builds vuln/fixed/asan | prints `ALL CHECKS PASS` (rc 0) twice: ASan `WRITE of size 16384` 0 bytes after an 8820-byte region in `send_samples`, chosen `de`/`ad` at offsets 8820/21384, 5/5 identical. Harness only; live RDP, PDU path, network and auth gate UNKNOWN. |

Freerdp2Shell was handed off at 19:19Z and admitted by the operator at
19:32Z under standing approval #6; the two-pane window, seed wall, charter
and task-file entry are live. Wake trigger units and the presentation.json
entry are owed from the person's full-flag sync (`docs/runtime-pin.md`),
never a bare `mishe sync`. The [brief](../reports/frontier-freerdp2shell.md)
pins the sources, harness digests and expected bytes for rungs 1-3 plus
harness-only rung 4; live RDP reachability and the post-auth gate stay
UNKNOWN.

## Provisioning details

- **Node prebuilts** (`lab/node2shell/provision.sh`): Node v24.22.2
  `48cc0e21…af75`, fixed v24.22.3 `4f2b175a…fcfb`. The fix diff is tracked at
  `lab/repro/node2shell-sourcepins/fix-ae9ab37d62.diff`.
- **Ruby sources** (`lab/ruby2shell/provision.sh`): 3.4.12 `db6c1479…ec90`,
  3.4.13 `6474dff9…9589`, fix patch `391b34b2…847a`, glibc 2.39 `malloc.c`
  `b89f737b…0f72`. Consumer gems are pinned in
  `lab/repro/ruby2shell-stageB-{http.ru,rails-setup.sh}`.
- **PHP sources**: `lab/php2shell/provision.sh` pins all PHP tarballs and the
  fix patch. `build-apache.sh` reconstructs the mod_php DSO recipe that was
  previously only in prose; `build-apache-plain.sh` builds the unsanitized
  `-g -O0` module used by the black-box and GDB Apache replay. The descendant
  session-filename UAF lane (CVE-2026-129481) replays with
  `lab/repro/php2shell-cve129481-fpm.py` against the pinned 8.4.27 FPM ASan
  build; 8.4.28 and a benign-close control are the negatives.
- **Mosquitto**: no published SHA-256 sidecar exists at the vendor path;
  `provision.sh` pins the exact local tarballs with hashes recorded from the
  audited files. cJSON 1.7.17 is pinned by `provision-cjson.sh`.
- **Brotli**: `run.sh` now aborts if the fetched PoC hash differs;
  trigger/stream hashes are recorded in the report.
- **Postgres/Dragonfly**: runners pull by tag but abort on image-digest
  mismatch against the values printed in the reports.
- **FreeRADIUS/FalkorDB**: both are small standalone C harnesses under
  `lab/frontier/<target>/`; `run.sh` rebuilds every variant and the briefs
  pin the source commits and artifact digests. FreeRADIUS vulnerable parent
  is `3f802d74deef`, fix `064567a08f3b`; FalkorDB vulnerable parent is
  `40780e992ecc`, fix `0b11a00b34b2`, which deletes the Bolt/WebSocket
  subsystem, so the lab `FIXED` build is a locally added length guard, not
  an upstream patch. The FreeRADIUS rung-4 claim is harness-only (known key,
  fixed stack layout); FalkorDB does not claim rung 4 at all. Live `radiusd`
  reachability and a live `BOLT_PORT` service remain UNKNOWN.
- **Freeswitch**: a standalone, file-only C harness under
  `lab/frontier/freeswitch2shell/`; `run.sh` rebuilds vuln/fixed/asan and
  writes `logs/digests.txt`. Vulnerable parent `fbac12b451a1` and fix
  `d557ca6d29e6da4f10824dc158100906a592b91a` are pinned in the brief. After
  the accounting and exit-code repair the driver prints `ALL CHECKS PASS`
  (rc 0) with pinned sources `ws_overflow.c` `75433b5d…` and `run.sh`
  `637cfa36…`. Its earlier 2928 OOB-write count was double the real extent:
  a zero-byte past-the-buffer read underflowed `trace_copy()` and added 1464
  phantom writes. No live FreeSWITCH process, WebSocket upgrade, real heap
  layout or loopback path was exercised; the rung-4 grade is harness-only
  and both config gates are off by default.

## Raw evidence policy

Large `logs/`, `build/`, `deps/`, corpora and site-local state stay ignored.
Each report quotes the exact bytes needed to grade its claims and states the
regeneration command. A witness re-run is identified by its tape event and
its committed harness; absence of a log in Git is never used as evidence of
absence of a result.

## Keeping this document true

The `docs` mind owns this page and the README. The `repo-change` producer
observes every git commit and wakes only `docs`; each wake must read
`signals/repo-change.detail`, fix or delete the stale passage in one scoped
commit, or record `doc-ok` with evidence. A new lane is not complete until its
provisioning, replay and reproducibility entry exist.
