# sqlitesession2shell harness provenance (2026-11-27)

All fetches were read-only provisioning from public sqlite.org, GitHub, the
CVE Program API and the researcher repository. All execution stayed local in
`lab/frontier/sqlitesession2shell/`; no network service, external probe,
socket target or other lab target was touched.

## CVE and claim verification

- CVE record `https://cveawg.mitre.org/api/cve/CVE-2026-119379` is PUBLISHED
  (VulnCheck, 2026-10-30): "SQLite before 3.54.0 ... heap buffer overflow ...
  `sessionUpdateFind()`", CWE-787. Its references include the patch
  `64459c87...`, fossil `3f57024aecea0f3b`, `version-3.53.4` source line 5619
  and the abraxaslabs write-up. This target is therefore CVE-2026-119379.
- Discrepancy preserved: the PoC README calls this "no CVE yet" (it discusses
  the older, closed CVE-2026-50812). The CVE record above postdates that
  README; no CVE number is taken from the README.
- `git ls-remote --tags https://github.com/sqlite/sqlite.git
  refs/tags/version-3.53.4 refs/tags/version-3.54.0` returned
  `b09c88c14082339b66c7b7158d609a771e64ca69` and
  `6932c59ee5c280599dfae9e7b431698a7cab9687`. Both release archives contain
  `manifest.tags` entries for those version tags; their fossil `manifest.uuid`
  values are recorded below and were independently printed by the harness via
  `sqlite3_sourceid()`.
- Verified by reproduction, not assumed: the 242-byte changeset, ASan WRITE,
  sink frame, pinned versions, vulnerable/fixed differential and plain-build
  behavior below were all observed on this host.

## Pins

| Item | Value |
|---|---|
| Vulnerable archive | `https://www.sqlite.org/2026/sqlite-src-3530400.zip` → `pins/vuln.zip` |
| vuln.zip SHA-256 | `d18fa15aec74d8c17e1463f861095adc01b5ad190256acb4f91d22f0368d232b` |
| vuln version / git tag SHA | `3.53.4` / `b09c88c14082339b66c7b7158d609a771e64ca69` |
| vuln fossil manifest / runtime source-id | `bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc` / `2026-07-24 19:02:57 bf7c7f30…` |
| vuln pinned session source SHA-256 | `403dfc4b8ef9a73f249e74e06f09314904199bc7cab56741f0caf1f43e3f7b66` |
| Fixed archive | `https://www.sqlite.org/2026/sqlite-src-3540000.zip` → `pins/fixed.zip` |
| fixed.zip SHA-256 | `8847659821e0c5116bd14a94644c82ba932b2d9a05ac81af2e34af814aad7c58` |
| fixed version / git tag SHA | `3.54.0` / `6932c59ee5c280599dfae9e7b431698a7cab9687` |
| fixed fossil manifest / runtime source-id | `be8d059e9a49089ab2dce5ed26dd87aaf598fdc5fbe0b107c0dd758464bcd5e3` / `2026-10-09 15:46:58 be8d059e…` |
| fixed pinned session source SHA-256 | `7e4675d27f20727de8472877d47a697d03d97ba9b21dd0dc3c597c095dbf8034` |
| Fix commit | git `64459c87cc702d600704fb77ee40ca1782398a52`, fossil `3f57024aecea0f3b565ed823cf94b085031c481fd6323c1f2e4319a53500864f` |
| Fix patch | `https://github.com/sqlite/sqlite/commit/64459c87cc702d600704fb77ee40ca1782398a52.patch` → `pins/fix.patch`, SHA-256 `d27f37e223efe4f066f0f7d66cf8dbc8bc4f2a995ca9adcb6cbe928bf8e52c42` |
| PoC repository | `https://github.com/abraxas/sqlite-session-ncol`, HEAD `00f7b25d7a8549a71c07a00e6a7d99a384c6f669`; `pins/poc/` holds `poc.c`, `README.md`, `Dockerfile`, `run.sh`, `poc.py`, `health.py`, `sqlite-session-ncol-Abraxas-Labs.py` |

All pin URLs, hashes, commits, fossil UUIDs and verification commands are also
machine-readable in `pins/tags.json`; `pins/SHA256SUMS` covers every pin file.

### Fixture provenance

The PoC repository publishes an encoder (`pins/poc/poc.c`) but no raw blob
file. The exact 242-byte changeset is published as hex inside the upstream fix
commit's new `ext/session/sessioncorrupt.test` (visible in `pins/fix.patch`).
`pins/changeset-trigger.bin` decodes that verbatim hex (SHA-256
`a5fd19bffb0cce234d4ec6b58b5977a2dbbe7ce9f17d3c54fe78e1d69ec81403`) and was
checked byte-for-byte against the PoC encoder output (28-byte first block,
214-byte second block): identical. `pins/changeset-control.bin` is the first
28 bytes (SHA-256 `4831369a4fc52bf1e79d9b9c6c816cbe6d26ed0197589d996c85cd812a6471b2`).
It is therefore an upstream fixture, not a hand-derived approximation; the
label "derived" applies only to the extraction/decoding step from published
hex into a binary file.

## Commands used

```sh
curl -fsSL https://www.sqlite.org/2026/sqlite-src-3530400.zip -o pins/vuln.zip
curl -fsSL https://www.sqlite.org/2026/sqlite-src-3540000.zip -o pins/fixed.zip
curl -fsSL https://github.com/sqlite/sqlite/commit/64459c87cc702d600704fb77ee40ca1782398a52.patch -o pins/fix.patch
git ls-remote --tags https://github.com/sqlite/sqlite.git refs/tags/version-3.53.4 refs/tags/version-3.54.0
git ls-remote https://github.com/abraxas/sqlite-session-ncol.git HEAD refs/heads/main
sh build-all.sh
sh run-all.sh
```

`build-all.sh` checks `pins/SHA256SUMS`, extracts each archive into an ignored
`src-*/` tree, generates the amalgamation with the pinned `./configure` and
`make sqlite3.c` (release zips omit it), and compiles the verbatim pinned
`sqlite3.c` plus `harness.c` in ASan and plain modes for both pins:

```sh
cc -std=c99 -O1 -g -fsanitize=address -fno-omit-frame-pointer \
  -DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_PREUPDATE_HOOK -I<root> \
  harness.c <root>/sqlite3.c -o harness-<pin>-asan -lm -lpthread -ldl
```

Plain mode uses the same command without `-fsanitize=address
-fno-omit-frame-pointer`. No upstream source file is edited. Host: Ubuntu
GCC `cc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`, `libasan.so.8`.

`harness.c` follows the published PoC's DB setup (`CREATE TABLE t(id INTEGER
PRIMARY KEY, v TEXT); INSERT INTO t VALUES(1,'old');`), `SQLITE_CHANGESET_OMIT`
conflict handler and `sqlite3changeset_apply()` call; it only additionally
loads the fixed fixture files and prints observed mode/version/result lines.

## Observed evidence (2026-11-27)

Raw sink lines: `ext/session/sqlite3session.c:4401` in the vulnerable pin
(`memset(p->aUpdateMask, 0, nU32*sizeof(u32));`), emitted into the generated
amalgamation at `sqlite3.c:238155`; the allocation is at amalgamation
`sqlite3.c:238148`. ASan exit code 134; `sh run-all.sh` exit code 0 with
`PASS=44 FAIL=0`. Exact runner SHA-256:
`f16b47cd967319c2cf12b67bb27984aac56c6ae055ee14b074a88cb9dfc361e8`.

Excerpt of `runs/vuln-asan-trigger.out`, raw `nl -ba` line numbers:

```text
     7	=================================================================
     8	==1431703==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000400 at pc 0x7f1fd78fa97d bp 0x7ffe3adc3b30 sp 0x7ffe3adc32d8
     9	WRITE of size 12 at 0x502000000400 thread T0
    10	    #0 0x7f1fd78fa97c in memset ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc:87
    11	    #1 0x62a849155472 in memset /usr/include/x86_64-linux-gnu/bits/string_fortified.h:59
    12	    #2 0x62a849155472 in sessionUpdateFind src-vuln/sqlite-src-3530400/sqlite3.c:238155
    13	    #3 0x62a849155472 in sessionApplyOneOp src-vuln/sqlite-src-3530400/sqlite3.c:238811
    14	    #4 0x62a849156580 in sessionApplyOneWithRetry src-vuln/sqlite-src-3530400/sqlite3.c:238899
    15	    #5 0x62a849161a15 in sessionChangesetApply src-vuln/sqlite-src-3530400/sqlite3.c:239473
    16	    #6 0x62a84916353b in sessionChangesetApplyV23 src-vuln/sqlite-src-3530400/sqlite3.c:239620
    17	    #7 0x62a849163993 in sqlite3changeset_apply src-vuln/sqlite-src-3530400/sqlite3.c:239703
    18	    #8 0x62a848f61122 in main /home/mesh-home/mishe-tauftauf2shell/lab/frontier/sqlitesession2shell/harness.c:96
    23	0x502000000400 is located 0 bytes after 16-byte region [0x5020000003f0,0x502000000400)
    24	allocated by thread T0 here:
    26	    #1 0x62a848ffff88 in sqlite3MemMalloc src-vuln/sqlite-src-3530400/sqlite3.c:28035
    30	    #5 0x62a8491554eb in sessionUpdateFind src-vuln/sqlite-src-3530400/sqlite3.c:238148
```

The 4-byte logical request (`nU32=(2+33)/32=1`) becomes `malloc(4+8)` in the
pinned `sqlite3MemMalloc`, which this allocator reports as a 16-byte region;
the 64-column second block computes `nU32=3` and memsets 12 bytes starting
exactly at the end of that region.

Differentials (all captured in ignored `runs/` files):

| Run | Observed |
|---|---|
| vuln ASan trigger (242 B) | rc 134, ASan heap-buffer-overflow, WRITE 12, 0 bytes after 16-byte region, `sessionUpdateFind` sink frame; no `apply-rc` line |
| vuln ASan control (28 B) | rc 0, `apply-rc=0`, no sanitizer report |
| fixed ASan trigger | rc 0, `apply-rc=0`, no sanitizer report |
| fixed ASan control | rc 0, `apply-rc=0`, no sanitizer report |
| vuln plain trigger | rc 139 (`Segmentation fault (core dumped)` from the shell), deterministic in 5/5 repeats; no sanitizer report, no `apply-rc` line |
| vuln plain control | rc 0, `apply-rc=0` |
| fixed plain trigger / control | rc 0, `apply-rc=0` |

## Negatives, failed hypotheses and limits

- The scout's "4-byte `aUpdateMask`, 12-byte memset 0 bytes past it" geometry
  is only partly right: the logical request is 4 bytes, but the **observed**
  ASan allocation is a 16-byte region. No 4-byte region appears in any report.
- A prior hypothesis that the 12-byte overwrite would stay inside the 16-byte
  allocation and leave the plain build clean is **disproved**: the plain
  vulnerable trigger reliably exits 139. No cause beyond the observed fault
  is claimed.
- The fixed pin still contains the same `memset()` text (at
  `ext/session/sqlite3session.c:4434`); its fix is upstream's `bNew` flag from
  changeset iteration, which forces the apply context to be rebuilt when a
  later block reuses a table name. Both pins were compiled verbatim.
- The published PoC's "success" line and Docker/loopback service were not
  used: no services, containers, sockets or external targets were run.
- No chosen-byte readback, pointer corruption, control-flow hijack, RCE, wire
  exploit or rung 4/rung 5 claim is made. The oracle is the ASan WRITE and the
  vulnerable-vs-fixed/plain differential only.

## Clean-archive-style replay (2026-11-27)

The 19 committed-intent files (this file, `.gitignore`, `HARNESS_SHA256.txt`,
`build-all.sh`, `run-all.sh`, `harness.c` and everything under `pins/`) were
copied by `tar` to a fresh absolute directory `/tmp/sqlitesession2shell-clean-replay`
with no `src-*/`, `runs/` or binaries present. Unmodified `sh build-all.sh`
returned rc 0 `BUILD_OK` after generating both amalgamations from the pinned
zips; unmodified `sh run-all.sh` returned rc 0 `PASS=44 FAIL=0` with the same
runner/harness/build/fix-patch hashes as `HARNESS_SHA256.txt`. This was an
author-side replay of the exact files intended for commit; `git archive` of
the parent commit and an independent witness replay remain owed.
