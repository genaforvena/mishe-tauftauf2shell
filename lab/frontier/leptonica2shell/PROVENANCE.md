# PROVENANCE — leptonica2shell staged evidence

Sources were fetched read-only from `github.com/DanBloomberg/leptonica` on
2026-11-25 during frontier W235. No external target was probed; all execution
was local under `lab/frontier/leptonica2shell/`.

## Pins

| artifact | origin | SHA-256 |
| --- | --- | --- |
| `pins/bytearray-1.87.0.c` | raw `src/bytearray.c` @ tag `1.87.0` | `b5740bbd65a5a7d18fa60220138411a5cc72ad838045e86d015889d835eccbc7` |
| `pins/bytearray-fixed.c` | raw `src/bytearray.c` @ `c493a776e6bc6cfb1d8d15152a0b74f3d15b33fd` | `e37f74fd680a917bc5c37a9b54d51e6ab242dd26fea6c30017e88c1b50e96e65` |
| `pins/array_internal-1.87.0.h` | raw `src/array_internal.h` @ `1.87.0` (L_Bytea layout only) | `6503883af8155c4e57daad609f8efdccc67d1c64b8ed6f8501cf0adc580d8fb7` |
| `pins/consts.inc` | verbatim `sed -n 75,77p pins/bytearray-1.87.0.c` | `25bd8f0a16b28e694ea55ea473fbe099858b42ab29e3db5ea6ac322d8d2462d9` |
| `pins/create-parent.inc` | verbatim `sed -n 97,113p pins/bytearray-1.87.0.c` | `571570525a8cbb69488c1a3a31b0390a25f11fa9f0e357eac558f30105bbb685` |
| `pins/stream-parent.inc` | verbatim `sed -n 176,196p pins/bytearray-1.87.0.c` | `5ed99ee58e3aac5be7906668a7266c9c60e880846d9b62123b1a7843c0dad32b` |
| `pins/create-fixed.inc` | verbatim `sed -n 97,115p pins/bytearray-fixed.c` | `a66cebd7340cecb55950175418ef0b4c353485e74b2b28becb0778f10d0f7a6f` |
| `pins/stream-fixed.inc` | verbatim `sed -n 178,202p pins/bytearray-fixed.c` | `b05ae0baca694553e4b4657fdfeb8f69bb0f356f3e160c5d2b2cbe0dac168eaf` |
| `harness/driver.c` | local harness | computed by `sha256sum` on replay |

Upstream fix patch:
https://github.com/DanBloomberg/leptonica/commit/c493a776e6bc6cfb1d8d15152a0b74f3d15b33fd.patch

## Verbatim versus stand-in

Verbatim: the two size constants, `l_byteaCreate()` and
`l_byteaInitFromStream()` from both commits, and the `L_Bytea` field layout
copied from the pinned `array_internal.h`. The `.inc` files are byte-identical
line ranges and are rehashed on every `run-all.sh` run.

Stand-ins: `l_binaryReadStream()` returns a read-only mmap of an unlinked
sparse file of size 1,000,000,001 (chosen marker bytes written with `pwrite`
at offsets 201, 256, 4096 and 65536); `LEPT_CALLOC` = `calloc`; `LEPT_FREE`
skips the mapped source pointer and otherwise calls `free`; `ERROR_PTR`
prints and returns its third argument; the `FILE *` argument is a non-NULL
opaque token. For the plain rung-4 observation only, `BOUNDED` replaces
`memcpy` with a 216-byte-capped synthetic consumer so chosen bytes past the
201-byte allocation can be read without running off the heap. No upstream
byte was edited.

## Commands and observed output

```
bash lab/frontier/leptonica2shell/run-all.sh
TOTAL: 17 PASS / 0 FAIL   (rc 0)
```

GCC ASan (`harness/out/vuln-asan.out`): `heap-buffer-overflow`, `WRITE of
size 1000000001`, `0 bytes after 201-byte region`, write frame
`l_byteaInitFromStream pins/stream-parent.inc:17`, allocation frame
`l_byteaCreate pins/create-parent.inc:9`. Clang ASan reports the same WRITE.
The fixed build reports `stream too large` and `BA=NULL` with no sanitizer
report; `LPTN_N=16` on the vulnerable build prints `NALLOC=17 SIZE=16` and is
clean. Plain bounded vulnerable build prints
`PAST_ALLOC=4d495348452d4c4550544f4e49434111` (chosen `MISHE-LEPTONICA` at
`data+201..215`); the fixed plain build prints `BA=NULL`.

Preserved harness negatives: the first fixed/safe runs crashed because
`LEPT_FREE` tried to `free()` the mmap source; the stand-in allocator was
added. A 512-byte bounded copy aborted on glibc heap metadata; the cap was
lowered to 216 bytes, within this build's usable chunk size. Both were local
harness defects, not upstream behavior; the pinned upstream bytes are
unchanged. Trace details containing PID/address/path are not used as evidence.
