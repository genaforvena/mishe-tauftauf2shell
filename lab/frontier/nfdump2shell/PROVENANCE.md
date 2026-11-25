# PROVENANCE — nfdump2shell staged evidence

All source was fetched read-only from `github.com/phaag/nfdump` on
2026-11-25 during frontier W234. No external target was probed; all
execution was local under `lab/frontier/nfdump2shell/`.

## Pins

| artifact | origin | SHA-256 |
| --- | --- | --- |
| `pins/nfd_raw-parent.c` | raw `src/netflow/nfd_raw.c` @ `8a00543aa5c7b25b7d3f7642fdf306fd9979f237` | `f946944aa4c65085af96dc56fb622e40fd4eb8c3662e8ba7f2336a9377f92869` |
| `pins/nfd_raw-fixed.c` | raw `src/netflow/nfd_raw.c` @ `32b9cbe7f17e099d59fc5eac71c84c6c6f051fa5` | `b6fbdd91fbac138ec1eac2c2becabcf82a59b9f46249979027cf086ceaa650ea` |
| `pins/nfxV3-parent.c` | raw `src/libnffile/nfxV3.c` @ parent | `408cbbc8859d62fe1002817d73c5b08800caa4640e107843af16a34de44ad0ae` |
| `pins/nfxV3-fixed.c` | raw `src/libnffile/nfxV3.c` @ fix | `d94b82d3d2a295c6692d3f03fc5b0ee06eb5f621ba7dcb6dcae1b3ef85cdf77e` |
| `pins/nfxV3.h` | raw `src/libnffile/nfxV3.h` @ parent | `84a6832819dc88ac988cf6518c37a083611c63a58c0fbea3b16f6f8ddf874247` |
| `pins/nfd_raw.h` | raw `src/netflow/nfd_raw.h` @ parent | `530d8851e3b1d9293fe484366e2694202fedbf4d165e62ddff29713666407efa` |
| `pins/nffile.h` | raw `src/libnffile/nffile.h` @ parent | `0e9573c595b546918355917c1278f5a1ae8a7c0b1f24da601a5c2b8d9402f870` |
| `pins/nffile_inline-parent.c` | raw `src/inline/nffile_inline.c` @ parent | `6a4c26fb91e603e3e83994b297d347a006a1c8f47a751d4c729f0fd222924c6e` |
| `pins/verify-parent.inc` | verbatim `sed -n 495,550p pins/nfxV3-parent.c` | `c020fe80a020eba2035b2a629f9437611d087c1ca9567c4911538ab9decf51d6` |
| `pins/verify-fixed.inc` | verbatim `sed -n 495,556p pins/nfxV3-fixed.c` | `0f66f0a3eb2b8cd4125c200d3875c564a66a6ce2147771b360342c56e8db0e16` |
| `pins/process-parent.inc` | verbatim `sed -n 136,320p pins/nfd_raw-parent.c` | `5c8857c7c6fd1b4ebc3af9ffea78e58f7b4e6fa8a6523a8c2a85982be4dd8cdb` |
| `pins/process-fixed.inc` | verbatim `sed -n 139,328p pins/nfd_raw-fixed.c` | `73473a1a48ad7ecfc2da0e8003f0c544861e450d14ea9c1a57baafb81f62a24c` |
| `harness/driver.c` | local harness | `96eb5fb9d2c59513b2a1136f69812c756c70f97821aff8def181fe2ea6f40a2d` |
| `run-all.sh` | local runner | `84daa3b2728fb8e9ab3053eff10de1b657e99cac21970e566c3a5f95c9851f19` |

Upstream fix patch: <https://github.com/phaag/nfdump/commit/32b9cbe7f17e099d59fc5eac71c84c6c6f051fa5.patch>

The GHSA id `GHSA-gpgq-hv9x-7mqj` came from this plant's scout/wall; both
`https://github.com/advisories/GHSA-gpgq-hv9x-7mqj` and the GitHub advisory
API returned HTTP 404 on 2026-11-25. No CVE id is claimed here. The fix
commit message is the verified ground truth for the primitive.

## What is pinned verbatim and what is a stand-in

Verbatim: the whole `nfxV3.h` struct/table/definitions, `VerifyV3Record()`
from both commits, `GetExtension()` + `Process_nfd()` from the parent,
`ScanExtensions()` + `Process_nfd()` from the fix. The `.inc` files are
byte-identical line ranges of the pinned sources (hashes above).

Stand-ins: `config.h` (empty) and `id.h` (`V3Record 11` copied from pinned
`src/libnffile/id.h`), `LogError`/`LogInfo`/`dbg_printf`, `getExporter()`,
`WriteBlock()`, `MetricExporterID()`, `UpdateMetric()`, `flow_record_short()`,
`ntohll()`, the output data block and stat record. The attack packet and
`FlowSource_t.received` are built in `harness/driver.c`.

## Commands and observed output

```
bash lab/frontier/nfdump2shell/run-all.sh
TOTAL: 10 PASS / 0 FAIL
```

GCC ASan (`harness/out/vuln-asan-attack.log`):

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 8 at 0x504000000040 thread T0
    #0 Process_nfd harness/../pins/process-parent.inc:121
    #1 main harness/driver.c:211
0x504000000040 is located 0 bytes after 48-byte region
allocated by malloc at harness/driver.c:148
SUMMARY: AddressSanitizer: heap-buffer-overflow ... Process_nfd
```

Clang ASan reports the same WRITE of size 8. The fixed build rejects the
short element (`Process_nfd: Corrupt nfd record: expected 1 records,
processd: 0`) and is ASan-clean; both vulnerable and fixed builds are clean
for the full 52-byte extension and for a record with no elements.

Plain vulnerable build with a 16-byte trailing canary region

(`harness/out/vuln-plain-attack-canary.log`):

```
ELEM_LEN=20 REC_SIZE=32 TOTAL=48
EXGENERICFLOW_SIZE=52 OFF_MSEC_RECEIVED=16
EXPECTED_BYTES=9b50351f49010000
CANARY_AFTER=9b50351f49010000
```

The written value is the harness-chosen `msecReceived` derived from
`fs.received` (`tv_sec=0x54415554`, `tv_usec=123000`); it is not
attacker-chosen on the wire. The fixed plain build leaves the canary at
`5a5a5a5a5a5a5a5a`.

Trace hashes that include PID/address/path are deliberately not used as
evidence; line numbers in `.inc` excerpts are relative to the excerpt, the
pinned source line numbers are recorded in the excerpt commands above.
