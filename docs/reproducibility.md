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
| PHP2Shell | [report](../reports/php2shell-investigation.md), [status](../reports/php2shell-status.md) | `bash lab/php2shell/provision.sh` | `bash lab/php2shell/build.sh`, `build-fpm.sh`, `build-apache.sh` | `lab/repro/php2shell-*.sh`, `*.py`, `*.gdb` |
| Node2Shell | [report](../reports/node2shell-investigation.md) | `bash lab/node2shell/provision.sh` | prebuilt binaries, no local source build | `sh lab/repro/node2shell-stageA.sh 5`; `lab/repro/node2shell-shrinkwalk/run-multi.sh` |
| Apache2Root | [report](../reports/apache2shell-investigation.md) | `lab/src/httpd-2.4.{70,71}.tar.bz2` + `.sha256` sidecars; `nghttp2-1.64.0.tar.xz` SHA-256 `88bb94c9…dd9` | `lab/frontier/apache2root/build.sh` | `oracle.sh`, `race.sh`, `lab/apache2shell/{sweep,gdb-inspect,drive.py}` |
| Mosquitto2Shell | [report](../reports/frontier-mosquitto2shell.md), [status](../reports/mosquitto2shell-status.md) | `bash lab/frontier/mosquitto2shell/provision.sh`, `bash …/provision-cjson.sh` | `build.sh`, `build-glibc.sh` | `run.sh`, `placement.sh`, `tcache_probe.py`, `pong_leak_probe.py` |
| Brotli2Shell | [report](../reports/frontier-brotli2shell.md) | `bash lab/frontier/brotli2shell/run.sh` fetches `poc.py` and verifies its SHA-256 | same script builds v1.2.0/v1.2.1/instrumented | same script writes `logs/` and prints digests |
| Postgres2Shell | [report](../reports/frontier-postgres2shell.md) | image digests pinned in `run.sh` | container images by digest | `./run.sh 17.11` and `./run.sh 17.12`; `trigger-vg.sql` for Valgrind |
| Dragonfly2Shell | [report](../reports/frontier-dragonfly2shell.md) | image digests pinned in `run.sh` | container images by digest | `./run.sh v1.40.1`, `./run.sh v1.40.2`; witness files in `lab/witness/dragonfly2shell/` |
| FreeRADIUS2Shell | [report](../reports/frontier-freeradius2shell.md) | see report | see report | see report |

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
  previously only in prose.
- **Mosquitto**: no published SHA-256 sidecar exists at the vendor path;
  `provision.sh` pins the exact local tarballs with hashes recorded from the
  audited files. cJSON 1.7.17 is pinned by `provision-cjson.sh`.
- **Brotli**: `run.sh` now aborts if the fetched PoC hash differs;
  trigger/stream hashes are recorded in the report.
- **Postgres/Dragonfly**: runners pull by tag but abort on image-digest
  mismatch against the values printed in the reports.

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
