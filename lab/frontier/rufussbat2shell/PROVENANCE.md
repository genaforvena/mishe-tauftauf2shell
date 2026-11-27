# rufussbat2shell — provenance and pins (W369, 2026-11-27)

## Claim and source pins

- GHSA-hcpc-vq8c-923h, published 2026-11-05, Moderate 6.5. No CVE ID in the
  advisory. Affected Rufus `>=4.11, <=4.16_BETA`; patched `4.16`.
  https://github.com/pbatard/rufus/security/advisories/GHSA-hcpc-vq8c-923h
- Vulnerable parent: `de4cf676c2aedf73b0ddfc234e420d19c8969c2e`.
- Fixed commit: `842873017f289713a5d5009320c11f31cfee36ed`.
- Full pinned vulnerable blobs fetched read-only from GitHub:
  - `src/parser.c` git blob `03757796073957daba6b8ed9eb13dd7b37866c80`,
    SHA-256 `35fa89ab4511e1b74306c411aba1997e86a0d38d411107a358eebe7d9e3aa16f`.
  - `src/rufus.h` git blob `6f1a9db53656f0a1fbe18007a34f927180f281d4`,
    SHA-256 `05308561ad8f3c590b8f5ef86e79b60784139ffd334c5e74b8f14586d49687b6`.
  - `src/stdlg.c` git blob `642a9e5f230e92c5bb727975a24a35ab4d07dc57`,
    SHA-256 `85a4711c01eca5d175c9c452b96ca870ab0e07b0724c1704fb91b15cd7881832`.
  - `src/hash.c` git blob `dc536d4a40e87ae467d12f48185d460262b0defe`,
    SHA-256 `954ffe0fb9afd7c1af0b855bccb9e4b03e9cfa199ab77e6f74898cfc51702c49`.
- Fixed `src/parser.c` git blob `9885e682f0d1e15cd37bc5b0bedf21eb77d9e8a7`,
  SHA-256 `cbe39d86a3794ff2d0f7911e30d4c79b9fedee316148f2f9e10acfcff5eeec26`.
  The other three pinned blobs are byte-identical across parent and fix.
- The committed `src/vuln/sbat.inc` and `src/fixed/sbat.inc` are verbatim
  function-body extractions with `#line` directives; the full upstream source
  trees are not duplicated in Git. `src/fix.patch` preserves the exact parser
  hunk from the fix commit.

## Source-bound mechanism

Vulnerable `src/parser.c:1626-1637` counts LF before converting CR to LF, then
allocates `(num_entries + 1) * sizeof(sbat_entry_t)`. With CR-only input the
allocation is 32 bytes on x86-64: exactly two 16-byte slots. The parse loop
writes one 16-byte entry per nonblank, nonzero-version line at `:1651-1671`.
Entry 2 therefore writes its 8-byte product pointer at offset 32 and its chosen
32-bit version at offset 40; the entry-2 NULL-product terminator is also out of
bounds. The fix moves CR conversion before the LF count, so 60 CR lines allocate
62 slots and keep the entry-60 terminator in bounds.

The real caller at `src/stdlg.c:1711-1724` downloads an unsigned response under
1 KB, calls `GetSbatEntries()`, then loops until a NULL product. The real later
consumer at `src/hash.c:2217-2223` walks the list with `strcmp`.

## Harness and commands

- `harness/driver.c` includes the pinned function and reads a local file into a
  `malloc(n + 2)` NUL-terminated buffer. It exercises either the real-style
  terminator loop or a synthetic adjacent victim.
- `harness/build.sh` builds ASan (`-O1 -g -fsanitize=address`) and plain
  (`-O0 -g -fno-stack-protector -fno-pie -no-pie`) arms. The plain marker arms
  use `-Wl,--wrap=calloc` to place a 24-byte victim immediately after the real
  list allocation; the victim callback is at victim offset 8, exactly where
  entry 2's version field lands.
- `harness/run-all.sh` checks the committed pins before and after regeneration,
  generates LF, CRLF, CR-60, CR-2 and three-line chosen version inputs under
  `evidence/`, rebuilds, and checks exact vulnerable/fixed, safe/attack,
  marker/not-called and one-byte-wrong-target controls.
- Replay from this directory: `./harness/run-all.sh`. The script runs
  `sha256sum -c SHA256SUMS` both before and after rebuilding and regenerating
  evidence, so `RUN_ALL_OK` also requires byte-identical stable outputs.
- Cross-compiler smoke: `CC=gcc ./harness/run-all.sh` and the default Clang run
  each reported `RUN_ALL_OK 11 PASS / 0 FAIL`.

## Observed evidence

- Vulnerable ASan CR-60 (350 bytes): `heap-buffer-overflow`, `WRITE of size 8`,
  0 bytes after a 32-byte region, `GetSbatEntries` at `src/parser.c:1651`.
- Vulnerable ASan CR-2: parser completes; terminator loop produces
  `heap-buffer-overflow`, `READ of size 8`, 0 bytes after the same 32-byte region.
- Fixed ASan CR-60: rc 0, `ENTRIES=60`; fixed CR-2: rc 0, `ENTRIES=2`.
- Vulnerable LF-3 and CRLF-3: rc 0, `ENTRIES=3`.
- Vulnerable marker arm, three CR lines with the chosen marker address as the
  third version: `PREFIX_IN_INPUT=1 CALLBACK=benign_marker`,
  `GUARD=1122334455667788`, then `BENIGN_MARKER`.
- Fixed marker arm with the same file: `PREFIX_IN_INPUT=0 CALLBACK=not_called`,
  unchanged guard, no marker. Vulnerable `not_called` and one-byte-wrong-target
  controls do not print the marker; vulnerable CR-2 leaves the victim unchanged.

The volatile ASan overflow/read logs contain PIDs and addresses and are
gitignored. Stable control outputs and the replay summary are pinned in
`SHA256SUMS`.

Clean replay: `git archive --format=tar 0415fa78 lab/frontier/rufussbat2shell`
TAR SHA-256 `178726d9f94a0bbf2e249431fc00576dccbb610cb9c912d41ea10cab18a9c025`
matched 16/16 `SHA256SUMS` pins and unmodified `./harness/run-all.sh` reported
`RUN_ALL_OK 11 PASS / 0 FAIL`.

## Scope limits

R3 is confirmed on the exact pinned parser. R4 is LIMITED to the synthetic
adjacent victim and no-PIE/no-canary build. The wrapper controls adjacency; it
does not model the Windows heap. No Rufus executable, Windows API, TLS request,
external host, loopback service, debugger-forced call, shell or command was
used. R5 is NOT CLAIMED. Real allocator adjacency, ASLR, CFG and the live
post-download object layout remain UNKNOWN.
