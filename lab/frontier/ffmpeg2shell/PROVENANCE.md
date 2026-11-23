# Provenance — ffmpeg2shell harness (W142, 2026-11-23)

CVE-2026-75143 / GHSA-7qc3-xqxj-426p. All provisioning was read-only fetching
of public upstream blobs and advisory pages; no external host was probed. The
harness runs only inside this directory with a direct function call, no socket,
listener, RIST peer, async thread or FFmpeg process.

## Pinned inputs

| File | SHA-256 | Origin |
|---|---|---|
| `src/librist.c.7b05d16c` | `bf749fb297ba1ff364d85867fc8a61ce253dfd9fac642dbfe5f2aed2221e9a7c` | raw.githubusercontent.com/FFmpeg/FFmpeg/7b05d16ce71d7525493354f2f725cded9dbc05d2/libavformat/librist.c (parent of the fix commit, advisory-confirmed vulnerable) |
| `src/librist.c.n9.0` | `bf749fb297ba1ff364d85867fc8a61ce253dfd9fac642dbfe5f2aed2221e9a7c` | raw.githubusercontent.com/FFmpeg/FFmpeg/n9.0/libavformat/librist.c (affected release, byte-identical to vulnerable parent) |
| `src/librist.c.1c10bcc2` | `531f4332f4f95d494b3356abbab72b6409cb70fc7c7054de55f4e136c36ecd1e` | raw.githubusercontent.com/FFmpeg/FFmpeg/1c10bcc2e17255dacb717a25ab3db142ce390602/libavformat/librist.c (fix commit) |
| `src/librist.c.n9.0.1` | `531f4332f4f95d494b3356abbab72b6409cb70fc7c7054de55f4e136c36ecd1e` | raw.githubusercontent.com/FFmpeg/FFmpeg/n9.0.1/libavformat/librist.c (patched release, byte-identical to fix commit) |
| `src/async.c.n9.0` | `52217f7c00a6c6b6cf8f60740b626119c4846654ccfe7ada897fa8cdd445fa57` | raw.githubusercontent.com/FFmpeg/FFmpeg/n9.0/libavformat/async.c (caller-size evidence: `to_copy = FFMIN(4096, fifo_space)` at line 235, `ffurl_read(c->inner, dst, *size)` at line 140) |
| `src/fix-1c10bcc2.patch` | `8a0afc205c45d5ef81dcfb156c4e2eda130763a0a890fa9008a8ba927cd9410e` | code.ffmpeg.org/FFmpeg/FFmpeg/commit/1c10bcc2e17255dacb717a25ab3db142ce390602.patch |
| `src/GHSA-7qc3-xqxj-426p.html` | `89964a99e60fe9a10c5538579fef4513f6580f2e7466d29b554ed3b3dd94fd97` | github.com/advisories/GHSA-7qc3-xqxj-426p |

The advisory reports "Affected versions: Unknown / Patched versions: Unknown".
Release-tag bytes were checked directly: `n7.1.3`, `n8.0`, `n8.0.1`, `n8.1`,
`n8.1.1` and `n9.0` carry the unclamped `size = data_block->payload_len;`;
`n9.0.1`, `n9.0.2` and `n9.1` carry the `FFMIN` clamp. The first release tag
observed with the fix is n9.0.1. No numeric range is claimed beyond this.

`src/SHA256SUMS` pins the seven files; `harness/SHA256SUMS` pins the driver,
runner, four generated slices and the seven source pins (13 entries).

## Verbatim slices re-extracted per run by `harness/run.sh`

| Slice | Vulnerable source | Fixed source |
|---|---|---|
| `vuln/librist_read.inc` | `librist.c.7b05d16c:200-234` | — |
| `rel90/librist_read.inc` | `librist.c.n9.0:200-234` | — |
| `fixed/librist_read.inc` | — | `librist.c.1c10bcc2:200-234` |
| `rel901/librist_read.inc` | — | `librist.c.n9.0.1:200-234` |

Each slice is the **complete upstream `librist_read()` function**, re-created
with an `echo '#line 200 "librist.c.<pin>"'` header followed by `sed -n
'200,234p'` of the pinned blob, so ASan and gdb attribute the fault to the
pinned line, not the generated file. Only the function's environment is
stubbed (librist types/calls, `URLContext`/`RISTContext`, error and log
macros). No socket, TLS, RIST peer, async thread or daemon.

## Harness inputs and stubs

The destination is a 4096-byte heap object, the size the real `async:`
background task can pass to the inner reader (`async.c:235` → `:140`). The
source is a 9972-byte RIST payload, the maximum that passes the vulnerable
`payload_len > MAX_PAYLOAD_SIZE` gate (`10000-28`). Chosen markers are placed
at payload offsets 4096 (0x41), 4113 (0x5a), 4120 (0x7a), 4128 (0x3c), 4136
(0x7b), 4144 (0x42), 4152 (0x7b) and 4160 (0x41). `mode=attack` uses the full
geometry; `mode=safe` uses a 4-byte payload; `mode=oversize` uses 9973 bytes to
exercise the existing gate. A 20000-byte adjacent heap object filled with
0xCC is allocated after the destination so the plain build's overwrite lands
in a live allocation rather than the top chunk; its measured distance is
`SINK_DIST=4112`. Plain builds use `-O0 -g -fno-stack-protector`; ASan builds
use gcc and clang with `-fsanitize=address` and `detect_leaks=0` (the driver
intentionally leaves its heap objects un-freed so no allocator action follows
the overflow).

The `flb`/librist stub types are a harness convenience: `payload_len` is a
signed `int` here. The pin, the verbatim function body and the fix hunk are the
contract; stub types are not claimed as upstream declarations.

## Observations

- `PASS=66 FAIL=0` three times (`evidence/run1.txt`…`run3.txt`) plus clean
  `/tmp` replay (`evidence/tmp-replay.txt`); normalized trace
  `6c3586c5d5b510b9619431873b157055c97edc32c5b6eda9967eb4feae61629f`.
- Rung 1: 9972-byte payload vs 4096-byte caller buffer, 5876 bytes over;
  both the payload cap and the caller cap are pinned to source lines.
- Rung 2: vulnerable parent and n9.0 return 9972 and copy every byte;
  fix and n9.0.1 return 4096, leave the adjacent object's 0xCC pattern intact
  (`SINK_BYTE_1=cc`, `SINK_BYTE_8=cc`); a 9973-byte payload is rejected with
  `RET=-5` in all four variants.
- Rung 3: gcc and clang ASan `heap-buffer-overflow`, `WRITE of size 9972`,
  at pinned `librist.c.7b05d16c:230` in `librist_read`, 0 bytes after a
  4096-byte region allocated in `main`; n9.0 shows the same WRITE; fixed,
  n9.0.1 and safe inputs are clean.
- Rung 4: chosen bytes at offsets 4096/4113/4120/4128/4136/4144/4152/4160
  and deep smear at 5000/9000; the adjacent object's data is overwritten with
  0x5a and 0x7a. gdb at pinned line 233 shows `$1 = 9972` and the chosen bytes
  in the frame for the vulnerable build, `$1 = 4096` and 0xCC for the fixed
  build.

## Ceiling / negatives

Direct call with stubbed librist/libavformat plumbing; no real FFmpeg process,
RIST socket, peer, wire, async thread/ring buffer, TLS/SRP or hostile sender.
No pointer control, ROP chain, command, marker file or witness verdict. The
adjacent 20000-byte sink is a harness artefact chosen to absorb the overwrite;
the layout of an actual async ring destination's neighbours is UNKNOWN.
Nothing here is remote command execution. Earlier attempts in this wake that
failed are preserved in `evidence/` as the corrected checks replaced them:
the first plain build aborted with `malloc(): corrupted top size` before it
could report (no adjacent object, stdout not buffered), LeakSanitizer noise
contaminated ASan controls, and gdb check strings assumed one-line byte dumps.

## Re-run

```
cd lab/frontier/ffmpeg2shell/harness && bash run.sh
```
Check `PASS=66 FAIL=0` and the trace hash above. A clean-room replay of
`git archive HEAD lab/frontier/ffmpeg2shell` is recorded in
`evidence/git-archive-replay.txt`.
