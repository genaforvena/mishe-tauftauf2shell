# Provenance — synchronet2shell W194 (2026-11-24)

All fetches below are read-only provisioning from public source hosts. No
external system was probed; all execution is local, no sockets.

## Advisory and fix

- INCIBE-CERT notice INCIBE-2026-937 / CVE-2026-133646:
  <https://www.incibe.es/en/incibe-cert/notices/aviso/out-bounds-write-synchronet-bbs-synchronet>
  (read 2026-11-24 ~02:38Z). NVD record read through
  `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-133646`.
- Fix commit `cb6d77dbca0d24fbffc2154a8437113196582810`, parent
  `42f586d70792e46b4934176976bc7949b312dede`, read from the public GitHub mirror
  API `https://api.github.com/repos/SynchronetBBS/sbbs/commits/cb6d77dbca`
  (the upstream GitLab page requires sign-in). One file changed,
  `src/sbbs3/answer.cpp`, 6 additions / 6 deletions.

## Pinned files (`PINS.sha256`, verified by `bootstrap.sh`)

Each file was fetched with `curl -fsSL` from the exact raw URL below and hashed
with `sha256sum`; `harness/gen.sh` extracts code only from these files.

| Pin | Source URL (ref / path) |
|---|---|
| `answer-parent.cpp` | `https://raw.githubusercontent.com/SynchronetBBS/sbbs/42f586d70792e46b4934176976bc7949b312dede/src/sbbs3/answer.cpp` |
| `answer-fixed.cpp` | `https://raw.githubusercontent.com/SynchronetBBS/sbbs/cb6d77dbca0d24fbffc2154a8437113196582810/src/sbbs3/answer.cpp` |
| `ssl.c` | same parent ref, `src/sbbs3/ssl.c` |
| `sbbs.h` | same parent ref, `src/sbbs3/sbbs.h` |
| `telnet.h` | same parent ref, `src/sbbs3/telnet.h` |
| `sbbsdefs.h` | same parent ref, `src/sbbs3/sbbsdefs.h` |
| `gen_defs.h` | same parent ref, `src/xpdev/gen_defs.h` |
| `cryptapi.c` | `https://raw.githubusercontent.com/cryptlib/cryptlib/main/cryptapi.c` |

`cryptapi.c` is from cryptlib `main` at fetch time (the Synchronet tree links
cryptlib externally); its only role is the source-bound observation at lines
2649–2710 that the API has no destination-size parameter. No cryptlib code is
compiled into the harness.

## Reproduce

```
cd lab/frontier/synchronet2shell
bash bootstrap.sh                 # offline pin verification + .inc extraction
bash harness/run-all.sh           # rebuild 7 binaries, 9 cases, evidence.log
```

Toolchain observed: g++ 13.3.0, clang++ 18.1.3, gcc libasan. All build products
under `build/` are local; `evidence.log` sha256 is written to `evidence.sha256`.

## Honest boundaries

The harness reproduces the pinned `answer()` statements, the pinned fixed helper
and a source-documented `cryptGetAttributeString` contract. It does not build
Synchronet or cryptlib, does not open an SSH connection, and does not exercise
the advisory's thread-blocking DoS. Rung 3 uses a reduced `REDZONE_MODEL`
struct; rung 4 uses the pinned field layout. No chosen-byte execution, pointer
control, witness replay or rung 5 claim.
