# Wazuh FIM sink harness — provenance

All fetches were read-only provisioning from public GitHub/NVD/VulnCheck;
all execution was local in this lab. No external target was contacted.

## Claims and exact records

- NVD `CVE-2026-74045`: `src/CVE-2026-74045.json`, fetched from
  `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-74045`,
  SHA-256 `bf7ece739405bf94382907a23b6fbc44e20332f213fd551eab869c65c4dd0f75`.
- GitHub advisory `GHSA-gc4j-j9fg-4cfr`: `src/GHSA-gc4j-j9fg-4cfr.html`,
  fetched from `https://github.com/wazuh/wazuh/security/advisories/GHSA-gc4j-j9fg-4cfr`,
  SHA-256 `02efdf88808ef4145075deddfdf2b475569a1aab78a244677858d35fedf62252`.
  It contains the PoC JSON, the 4.14.6/4.14.7 md5 equality claim, the A/B
  daemon result, the enrolled-agent 1514 claim and the explicit no-RCE scope.
- VulnCheck advisory (secondary):
  `https://www.vulncheck.com/advisories/wazuh-3.12.0-before-4.14.8-heap-buffer-overflow-in-wazuh-analysisd-fim-decoder`.
- Release reference: `https://github.com/wazuh/wazuh/releases/tag/v4.14.8`.

## Pinned upstream bytes

Fetched with `curl` from `raw.githubusercontent.com/wazuh/wazuh/<tag>/<path>`:

| file | tag | SHA-256 |
| --- | --- | --- |
| `src/syscheck.c.v4.14.7` | v4.14.7 | `7b3b7c666c5e9dde0d843efb2de37b99b51664bb30b8dda6841e3af8f0f1cadc` |
| `src/syscheck.c.v4.14.8` | v4.14.8 | `365542f76b9d3279cdb8cbc450a5b3f3adb1afa80cd1e0786879a3f79fb540b1` |
| `src/cleanevent.c.v4.14.7` | v4.14.7 | `bdb537181a19caf3e55f809bb36686445e7f8d91f2e3eaeb7ac7d131b2defcd6` |
| `src/cleanevent.c.v4.14.8` | v4.14.8 | `bdb537181a19caf3e55f809bb36686445e7f8d91f2e3eaeb7ac7d131b2defcd6` |
| `src/defs.h` | v4.14.7 | `7c1f285078c395a4aedf6301abd904b60b6f11a7c4b8e387f45b868e24ed8f32` |
| `src/eventinfo.h` | v4.14.7 | `924d6ba7dc3097ad08e54a27ff9840abd94af29e1eaf38f1c4dec94bdf71b743` |
| `src/syscheck_op.h` | v4.14.7 | `49d55bd71f2ad36c45aad5220054cc1a3919c0d7dacaf18184bc552f16312be1` |
| `src/syscheck_op.v4.14.8.h` | v4.14.8 | `afba91075ffe546d39e04fd58d95449f795cf8a67806db6ba9ccd68192172d8a` |
| `src/cJSON.h` | DaveGamble/cJSON v1.7.17 | `c01a8ca5609bb2c956dd1ae836d5d926ec68153ecebc5a75ea0febc2e076da8d` |

The complete manifest is `src/SHA256SUMS`. `cleanevent.c` is byte-identical
between the two tags: the input-sized allocation is unchanged; only the
decoder's output sizing changed. `diff -u` of the two `syscheck.c` files shows
the fix at v4.14.7:1680 → v4.14.8:1688 and the free-and-resize at
v4.14.8:1717-1723. The fixed tag also adds two audit-field enum values,
which the harness conditionally mirrors with `-DWZ_FIXED`.

## Build and replay

```
cd lab/frontier/wazuh2shell
bash run.sh out-direct
```

`run.sh` extracts four top-level functions verbatim from each pinned
`syscheck.c` by definition signature (no hand-edited sink bytes):

- v4.14.7: `fim_generate_alert` 1521-1708, `fim_generate_comment`
  1712-1722, `fim_fetch_attributes` 1744-1751,
  `fim_fetch_attributes_state` 1753-1836;
- v4.14.8: same functions at 1525-1712, 1733-1743, 1765-1772, 1774-1857.

Derived slices: `out-direct/build/extracted.v4.14.7.inc` SHA-256
`202e562d0c1a6352f8769422499ef8a7e202e8b49ac9ce2436f04dce8b60e846`,
`out-direct/build/extracted.v4.14.8.inc` SHA-256
`1942a273457cb63bab7e853090e017d502e4135f914e1c632576021080d7eb49`.

Compiler: `gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`. ASan builds use
`-fsanitize=address -fno-omit-frame-pointer -g -O0` and
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=0`; plain builds use `-g -O0`.
Both link the host `libcjson.so.1.7.17` against the pinned v1.7.17 header.
`harness.c` supplies the `Eventinfo` shape, allocator macros, `w_long_str`,
`wm_strcat`, `mdebug*`, and a `perm_json_to_old_format` stub that is not
exercised by the PoC (string `perm`, not object form). The JSON is the
advisory PoC with `hash_sha256` changed from `a` to `Q` (same byte length,
so the 459-byte allocation is unchanged) to make the written byte
identifiable. The allocation is `2*(strlen(json)+1)+1`, copied from
`cleanevent.c:59-62`.

Stable trace (PIDs, addresses and paths removed):
`out-direct/trace.txt`, SHA-256
`18055e124a8dd9d8dfda5c04ef3d5d27e0bb81d5897620b3d0ae0d186f433aa6`.
The authoritative content is the file itself.
Raw logs are `out-direct/{v4.14.7,v4.14.8}-{exploit,control}.log`
and `out-direct/plain-*`. Full ASan frames include the PID and heap address
and are therefore not byte-stable across replays.

## Observed results (2026-11-22 01:56Z)

- v4.14.7 exploit, ASan: `heap-buffer-overflow`, `WRITE of size 528`,
  0 bytes after the 459-byte `full_log` region; frame
  `fim_generate_alert (extracted.inc:266)` → `run_case` → `main`.
- v4.14.7 control (full `old_attributes`, 406-byte input, 815-byte alloc):
  rc 0, 93-byte output, no ASan report.
- Plain v4.14.7 exploit: 527-byte output, adjacent 128-byte neighbour
  changed from all `Z` to `: 'Q'` — the chosen JSON byte lands past the
  allocation. Plain control: neighbour unchanged.
- v4.14.8 exploit and control: rc 0, no ASan report; plain v4.14.8 exploit
  neighbour unchanged. The fixed sink formats into a stack `alert[OS_MAXSTR]`
  and reallocates `full_log` with `os_strdup` before use.

## Boundaries

This is a direct-call harness on verbatim upstream function bodies with
stubbed helpers, not a built `wazuh-analysisd` and not the enrolled-agent
1514 path. Wire reach, live daemon crash and the advisory's remote A/B are
claims not replayed here. No command execution or benign marker; no rung 5.
