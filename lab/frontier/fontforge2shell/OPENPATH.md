# OPENPATH — the same overflow through real font-OPEN, not Import (W8, 2026-11-24 21:0xZ)

Scope: real headless FontForge 20251009, the same local vulnerable plain /
patched plain / ASan / patched-ASan builds used in W1-W7. Author-side only,
independently unwitnessed. NO grade change: witness #3309 stays rungs 1-4
ESTABLISHED at the direct-call scope, NO r5. This closes the "Import() is the
only real entry point" gap at the labeled headless scripting scope with a
distinct user-facing path: opening a `.pcf` font file.

## Source-bound path

`Open("truncated.pcf")` -> `bOpen` (`scripting.c:1803`) -> `LoadSplineFont`
(`splinefont.c:1420`) -> `ReadSplineFont` (:1369) -> `_ReadSplineFont`,
which dispatches this file's magic at :1233 (`\1fcp`) and any `.pcf`/`.pmf`
suffix at :1272 to `SFFromBDF`. `SFFromBDF` (`fvimportbdf.c:2442`) calls
`SFImportBDF(sf, filename, ispk=2, toback=0, map)`, which reaches
`PcfParse:1831` -> `PcfReadEncodingsNames` and the same unchecked
`getformint16()` EOF->`-1` write at `fvimportbdf.c:1751`. Backtrace proof:
`gdb-open-bt.out` frames #0-#9 (sha256
`50072afff8315231525ab23eeb1b9c5280004f5d38ecf9b3b2837574b81b0806`;
command `gdb-open-bt.cmd` sha256
`aa183b5dce28efff494a60ef464068d2a555863e571b406f05efe4cc71f97185`).

## Inputs and commands

`open-path.ff` (sha256 `f605342b97378ff806752d844a0686b5e0c6b6c3335cbd52b56ada9f2638a675`)
is `Open("/home/mesh-home/mishe-tauftauf2shell/lab/frontier/fontforge2shell/truncated.pcf")`.
It reuses the pinned `truncated.pcf` unchanged; no new PCF was synthesized.
`open-complete.ff` (sha256
`02081ff64b84231c30381bd6a8babe3c9830e83e719a7cfb7a435d8b4b09885f`)
opens the pinned in-bounds `complete.pcf` as the safe-input control.

    cd lab/frontier/fontforge2shell
    for b in build-plain build-fixed-plain build-asan build-fixed; do
      ASAN_OPTIONS=detect_leaks=0 ./$b/bin/fontforge -script open-path.ff > open-$b.out 2>&1
      echo "$b rc=$?"
    done
    for b in build-plain build-asan; do
      ASAN_OPTIONS=detect_leaks=0 ./$b/bin/fontforge -script open-complete.ff > open-complete-$b.out 2>&1
      echo "control $b rc=$?"
    done

## Measured result

| build / input | rc | observation |
|---|---|---|
| vulnerable plain, `open-path.ff` | 134 | `double free or corruption (out)` (`open-build-plain.out`, sha256 `3021d38c691f907118df42d436b614d4d63765e39ce5d928a85b7f79c2aec53f`) |
| vulnerable ASan, `open-path.ff` | 1 | `WRITE of size 4`, `4 bytes before 16-byte region`, `PcfReadEncodingsNames ... :1751` (`open-build-asan.out`, sha256 `cafacc23c3f468b0c15b6ec8e6053b4125f7256c0ef432c6bb6f9e37ebb876d1`) |
| patched plain, `open-path.ff` | 0 | clean (`open-build-fixed-plain.out`, sha256 `60f02f9522adc006c7950b7770eb724d2a768c22cef2898eb44125bc18dae482`) |
| patched ASan, `open-path.ff` | 0 | clean (`open-build-fixed.out`, sha256 `48d87e242e1aa8d623ef3b066ee056756d49b9dc249516bb6d16130cf43c93c5`) |
| vulnerable plain/ASan, `open-complete.ff` | 0 / 0 | clean (`open-complete-build-plain.out` sha256 `ce8173e7f6298283725788d3131e4335f1f72a07a004c87158a2c00cd364eaaf`; `open-complete-build-asan.out` sha256 `c1ac99c903a1e4e484f2ef236806c40c58c60da4381acf95bb53c04673a19fe5`) |

`gdb -q -batch -x gdb-open-path.cmd ./build-plain/bin/fontforge`
(`gdb-open-path.out` sha256
`e1723cb9c6d99cbdb1eab5e54f66473798186f935b6b46ca5d08781b7d000091`;
`gdb-open-path.cmd` is `gdb-real-plain.cmd` with the script name changed,
sha256 `f128de1566db5c0befeff96a340219a2e7196893e24942cf15ce6fa9b28d9974`)
reports `glyph=-1 i=3 encs=0x555555c49290 b->glyphcnt=4`, fields
`min2=21318 max2=21318 min1=77 max1=80 tot=4`, RHS `0x53494d`; the hardware
watch on `*(int*)((char*)encs-4)` fired with `Old value = 0`,
`New value = 5458253`, and `x/4xb &encs[-1]` read
`4d 49 53 00` ("MIS\0") at `encs-4`. These are the same three file-chosen
bytes as the Import path (W2), now observed on the file-OPEN path. The top
byte is structurally zero from the 16-bit arithmetic.

## Negative lane preserved

`fontforge truncated.pcf` with NO `-script` exits 0 on both plain and ASan;
its stdout is byte-identical to the complete-table control (sha256
`ce8173e7……364eaaf` / `c1ac99c9……73a19fe5` in `open-cli-build-plain.out`
and `open-cli-build-asan.out`). Headless CLI without a script does not call
`LoadSplineFont`, so bare command-line file open is NOT claimed as a
trigger here. The GUI File->Open menu remains unavailable (`gtk+-3.0`
missing, all builds `ENABLE_GUI=OFF`).

## Limits

No pointer/IP control, command execution, ASLR/grooming study, network path
or independent witness verdict on this path. Three chosen bytes in a real
heap overflow are file integers, not an address. NO r5. Any new claim goes
to `witness`.
