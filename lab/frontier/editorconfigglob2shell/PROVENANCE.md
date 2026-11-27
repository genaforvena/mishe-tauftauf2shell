# Provenance — editorconfigglob2shell

All provisioning was read-only fetching of public sources; all execution was
local CLI/file I/O. No network I/O from the harness, no loopback listener, no
external probe.

## Advisory and fix

- CVE-2026-40489 / GHSA-97xg-vrcq-254h, OSV record fetched from
  `https://api.osv.dev/v1/vulns/CVE-2026-40489` — SHA-256
  `7a0fb8230c7f78e277e6d74ba20e92c3566dc22ca80c9e88d91b0c10df39c911`.
  Versions `<=0.12.10` affected, `0.12.11` fixed; CWE-121/787; the record
  says the earlier `pcre_str` fix (CVE-2023-0341) left `l_pattern[8194]`
  unguarded.
- Upstream fix commit
  `https://github.com/editorconfig/editorconfig-core-c/commit/5159be88ad50641d9843289adda791ba300421ff`
  (single parent `b4724e475571`), patch fetched from the `.patch` URL —
  SHA-256 `3055f837dbaa155e9e846767e91b5a395ef08c34df6458006aeb0ca4071e249f`.
  It adds `pattern_len`, rejects `pattern_len >= sizeof(l_pattern)` and
  replaces `strcpy` with bounded `memcpy`.
- Vulnerable source at that exact parent fetched from
  `https://codeload.github.com/editorconfig/editorconfig-core-c/tar.gz/b4724e475571`
  — SHA-256 `6309609579e8ac08e0f0e3a471fffc13ccbfdc5c6df2c905c4f2d82dbf652f54`.
  Sink: `src/lib/ec_glob.c:95` `char l_pattern[2 * PATTERN_MAX]`, `:100`
  `strcpy(l_pattern, pattern)`; real caller `src/lib/editorconfig.c:268`
  `ec_glob(pattern, hfparam->full_filename)` from `ini_handler`.
- Section bound is `MAX_SECTION_NAME 4096` at `src/lib/ini.h:80`; the
  directory part is escaped one byte per `?[]\\*-{},` character at
  `src/lib/editorconfig.c:250-258`, so a physical directory path of ~3.1 KB
  made from `*` components builds a >10 KB pattern without exceeding
  `PATH_MAX`.

## Harness pins

`SHA256SUMS` holds `advisory.json`, `fix.patch`, `source-parent.tar.gz`,
`harness/ecglob_harness.c`, `harness/make-case.py` and `build-real.sh`.
`run-all.sh` and its own outputs are not self-pinned. `sh run-all.sh`
verifies 6/6 pins, rebuilds four consumers offline from the pinned archive
(CMake + GCC 13.3.0, glibc 2.39, x86-64, `-g -O0`, ASan/plain, no stack
protector), generates attack and safe trees under `work/`, and reports
`RUN_ALL_OK 27 PASS / 0 FAIL`. The observed summary SHA-256 in this checkout
is `2de80df12d64a14d968b7183f7daf059eec107b1468b0c632b7858e26f5b074c`;
ASan addresses and PIDs are not pinned.

## Duplicates

No EditorConfig or `ec_glob` slug existed in `reports/`, `lab/frontier/` or
the frontier wall's admitted/screened/backups lists before this wake.
