# PROVENANCE — inihlongline2shell (CVE-2025-71450 / GHSA-gh7m-xpp3-w3vq)

## Provisioning (read-only public sources, 2026-11-26 W288)

All blobs were fetched with `curl -fsSL` into `pins/`; digests are in
`pins/PIN_HASHES.txt` and were checked with `sha256sum -c`.

| Blob | Source | SHA-256 |
|---|---|---|
| `inih-r62.tar.gz` | `https://codeload.github.com/benhoyt/inih/tar.gz/refs/tags/r62` | `9c15fa751bb8093d042dae1b9f125eb45198c32c6704cd5481ccde460d4f8151` |
| `inih-r63.tar.gz` | `https://codeload.github.com/benhoyt/inih/tar.gz/refs/tags/r63` | `5d7967de62c5bfdc4f9f5ab06ce44c9e498bae021c7dac5792c0696e76aa9963` |
| `fix-8e06f6b77b5.patch` | `https://github.com/benhoyt/inih/commit/8e06f6b77b5d4471bdc6d85ada81b67d37354a5c.patch` | `cabe4da5d97b39e41e934f812632d321be9b24c6d8e7a2f52dc45eb9d95cd3d6` |

Claim pages read this wake: `https://github.com/advisories/GHSA-gh7m-xpp3-w3vq`
(CVE-2025-71450, published 2026-11-02, updated 2026-11-06); upstream
issue `https://github.com/benhoyt/inih/issues/223`, PR
`https://github.com/benhoyt/inih/pull/206`, fix commit URL above, release
tag `https://github.com/benhoyt/inih/releases/tag/r63`. GitHub's package
and version fields for this GHSA read "Unknown"; the tag pair is the
pinned authority. No external system was contacted beyond these reads.

## Source-bound mechanism

- r62 `ini.c:165-169`: `abyss[strlen(abyss) - 1] == '\n'` inside the
  overlong-line discard loop with `char abyss[16]` at `:123`.
- Fix patch hunk `@@ -164,7 +165,8 @@`: adds `size_t abyss_len;`, caches
  `strlen(abyss)`, and guards `abyss_len > 0`. No other hunk.
- r63 `ini.c` carries the guard; both `ini.h` files define
  `INI_MAX_LINE 200` and `INI_INITIAL_ALLOC 200`.

## Harness and exact input

- `harness.c`: calls the shipped `ini_parse_file()` with a callback that
  always returns 1. No parser logic is reimplemented.
- `run-all.sh`: builds `harness-asan-r62`, `harness-asan-r63`,
  `harness-plain-r62`, `harness-plain-r63` with GCC
  `-fsanitize=address -fno-omit-frame-pointer -O0 -g` (and plain for the
  control builds), then runs five local-file cases and checks eight
  observable assertions.
- `evidence/attack.ini`: 199 bytes `A` followed by one `0x00`.
  `evidence/safe.ini`: same 199 `A`s followed by `\nkey=value\n`.

## Observations

`runs/r62-attack-asan.out`: `AddressSanitizer: stack-buffer-underflow`,
`READ of size 1`, frame `#0 ini_parse_stream src/inih-r62/ini.c:167`,
`#1 ini_parse_file src/inih-r62/ini.c:268`, frame object
`[48, 64) 'abyss' (line 123) <== Memory access at offset 47 underflows this variable`,
rc 1 in `runs/r62-attack-asan.rc`.
`runs/r63-attack-asan.out`, `runs/r62-safe-asan.out`,
`runs/r63-safe-asan.out`: rc 0, no `AddressSanitizer` string.
`runs/r62-attack-plain.out`: rc 0 (preserved negative — no plain-build
crash, no rung-1 or rung-2 claim).

`run-all.sh` result at 21:21Z: **PASS=8 FAIL=0**.

## Grade and limits

Rung 3 ASan-confirmed one-byte stack under-read via shipped API. Rung 4 NOT
CLAIMED: the index is fixed at `-1`, the read is one byte, no chosen offset,
no write, no pointer, no marker, no command. Rung 5 NOT CLAIMED: local file
input only, no wire path or live service. Addresses and PIDs in raw traces
are run-specific and excluded from trace hashes.
