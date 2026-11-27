# sailpsd2shell — provisioning and evidence provenance (frontier W315)

All fetches were read-only provisioning from public sources on 2026-11-27.
No external system was probed. All decode inputs and builds stayed under
`lab/frontier/sailpsd2shell/`; no network caller was started.

## Claims and exact URLs

- Advisory: `https://github.com/HappySeaFox/sail/security/advisories/GHSA-ccqf-rv86-h3wm`
  (CVE-2026-54627, published 2026-06-07, Critical CVSS 9.8, CWE-122/CWE-787,
  affected `<= 0.9.10`, patched `1.0.0`).
- Source archives: `https://codeload.github.com/HappySeaFox/sail/tar.gz/refs/tags/v0.9.10`
  and `.../refs/tags/v1.0.0`. The bytes are the same archives already pinned by
  `sailtga2shell`; they were copied locally, not fetched again.
- Tag identities verified through the GitHub tags API and shallow clones:
  `v0.9.10` = `cdd9d5f20bd0bf83683637afee61dd7e954162b2`,
  `v1.0.0` = `0f969168b9d19d43f448d2237990ec247ba822ca`.
- Fix: `https://github.com/HappySeaFox/sail/commit/f44a8b779a1fc527fc6bc5caa71a66a8ed940d50`
  (`PSD: Reject bitmap/indexed mode and depth mismatches before decode as
  reported in GHSA-ccqf-rv86-h3wm`), parent
  `fa24bceb93958ad665dbc3cf6b49a1079ab12559`.
- Raw fix files:
  `https://raw.githubusercontent.com/HappySeaFox/sail/fa24bceb93958ad665dbc3cf6b49a1079ab12559/src/sail-codecs/psd/helpers.c`
  and the same path at `f44a8b779a1fc527fc6bc5caa71a66a8ed940d50`.

## Pins (SHA-256)

| artifact | SHA-256 |
|---|---|
| `src-v0.9.10.tar.gz` | `dc0d6fa87cb4fa8b514f450a3fb13cee6e3e60f03250f683564fabbec0f722e3` |
| `src-v1.0.0.tar.gz` | `b6f77d6d451b72202c8e11bd5057b697a21f7b6c4ef713f19a96de5a16c08916` |
| `pinned/psd-v0.9.10.c` | `9d661a5769e17028075013649de8de7a15cd3f9ca7cd67e92fcff68a7d1d3627` |
| `pinned/psd-helpers-v0.9.10.c` | `789ac9b15b9f10d551ac5dc3f98fdf5341d50c3b6dc85323adcbe2be405920b4` |
| `pinned/psd-helpers-fix-parent.c` | `23362356da6c75b4c0c65368fd8181d9190f7eedb7ec2460b9af2755c6367501` |
| `pinned/psd-helpers-fix.c` | `f3f7f3fd5a1b071a3eef8349f56c1aa128c88a8ec0d44cdccf021b5c407c017d` |
| `pinned/psd-v1.0.0.c` | `33905062c111999ce39b0677ef5a7613980a540fbe3e87ee51da854086eec588` |
| `pinned/psd-helpers-v1.0.0.c` | `f3f7f3fd5a1b071a3eef8349f56c1aa128c88a8ec0d44cdccf021b5c407c017d` |
| `driver.c` | `034c859db4acd1ca387baf8857099e0cb42b89845a10ea5e12f3cab39e876d22` |
| `probe.c` | `f61b4efcff7e5e9a0cd103b7905365003fcd8b7c8b2e4c62382cc6e83750fafa` |
| `make-poc.py` | `73d4d7c4bab0ace8b9db983b301fa805d64109d6fedecb61bfb92146af872fe3` |
| `run-all.sh` | `62f795f1ef26eaf75ac29db4291164511adf9ddb8412fc212f24758f4f19c463` |
| `run-probe.sh` | `a19c4f97a7a085c1cbc69dd73b9c4576de1e663cb34b66943061a7c9a86a52f5` |
| `stubs/libavutil/pixfmt.h` | `b452ef37e3308339924e62eadf0ce7d4674732953927f745423b10ab60dd422e` |
| `stubs/libswscale/swscale.h` | `b452ef37e3308339924e62eadf0ce7d4674732953927f745423b10ab60dd422e` |

Generated inputs:

| artifact | bytes | SHA-256 |
|---|---:|---|
| `evidence/attack.psd` | 104 | `313b5a92436ab4f1ea66e64a2ab98734252a32be7dda4cd1be158c76c7326cd9` |
| `evidence/safe-depth1.psd` | 48 | `a3c07560cfd8c693b68ad55602d425fed9dff80c3559ec5c8124bceaadf093ed` |

The attack is the advisory's 8x8, one-channel, Bitmap-mode, depth-8,
uncompressed PSD with the final eight payload bytes changed to
`10 11 12 13 14 15 16 17`. The safe control keeps the same geometry and
matching depth 1.

## Source-bound mechanism

Vulnerable `src/sail-codecs/psd/helpers.c:55-59` maps Bitmap mode with one
channel to `SAIL_PIXEL_FORMAT_BPP1_INDEXED` without checking `depth`.
`sail_load_next_frame()` therefore allocates `height * bytes_per_line` =
`8 * 1` = 8 bytes for the pixels. The decoder accepts depth 8, reads eight
bytes per row, and at raw `src/sail-codecs/psd/psd.c:351-355` executes:

```c
for (unsigned pixel = 0; pixel < image->width; pixel++) {
    unsigned char* scan = (unsigned char*)sail_scan_line(image, row) + pixel * bpp;
    *(scan + channel)   = *(psd_state->scan_buffer + pixel);
}
```

`sail_scan_line(image, row)` advances by the one-byte Bitmap stride. For the
last row, the eight stores land at offsets 7..14: seven bytes past the 8-byte
allocation. The final payload byte at each offset wins because later rows
overlap earlier ones. Fix `f44a8b7` adds a nested `depth` switch: Bitmap accepts
only depth 1 and Indexed accepts only depth 8. The v1.0.0 helper is
byte-identical to the fix commit's helper.

## Builds and observed results

Environment: Linux x86_64, gcc 13.3.0, clang 18, CMake 3.28.3, Ninja.
`bash run-all.sh` extracts the pinned archives and builds five real static
SAIL PSD-only trees: gcc ASan vulnerable, clang ASan vulnerable, gcc plain
vulnerable, clang ASan fixed, gcc plain fixed. A 25-line driver calls only
`sail_load_from_file()` and propagates its status. No upstream source byte is
modified. Empty optional libswscale/libavutil stub headers are used only with
`SAIL_MANIP_USE_SWSCALE=OFF`.

Author run at 05:2xZ:

- `bash run-all.sh`: rc 0, **42 PASS / 0 FAIL**.
- GCC and Clang ASan: `heap-buffer-overflow`, `WRITE of size 1`, raw
  `psd.c:354`, zero bytes after an 8-byte region allocated by
  `sail_load_next_frame()`; caller `sail_load_from_file()`.
- Vulnerable depth-1 control: rc 0, ASan clean.
- Fixed 1.0.0 attack: rejected with `SAIL_ERROR_UNSUPPORTED_PIXEL_FORMAT`
  (`rc=201`), ASan clean; fixed depth-1 control rc 0.
- Plain vulnerable attack: rc 0. The seven-byte overrun fits this small glibc
  chunk's usable slack; no natural adjacent-object corruption is claimed.

`bash run-probe.sh` re-runs the 42/0 matrix, then links plain vulnerable and
fixed trees with `-Wl,--wrap=sail_malloc -Wl,--wrap=sail_free`. The probe
returns exact 8-byte static slots followed by eight visible guard bytes for
active `sail_malloc(8, &ptr)` calls and suppresses frees of those slots.
Author run: rc 0, **12 PASS / 0 FAIL**. The real decoder produces:

```text
slot00 data=1011121314151617 guard=cccccccccccccccc
slot01 data=4141414141414110 guard=11121314151617cc
```

Slot 00 is the codec scan buffer; slot 01 is the pixel allocation. Chosen
bytes `11..17` appear at pixel-buffer offsets 8..14 and offset 15 remains
`cc`. Vulnerable depth-1, fixed attack and fixed depth-1 controls contain no
chosen guard pattern.

## Negatives, discrepancies and limits

- The advisory's pasted ASan frame says `psd.c:371`; the pinned v0.9.10 raw
  sink is `psd.c:354`. The pinned v1.0.0 source has shifted lines and rejects
  the input. The paste also logs `Version: 1.0.0` while describing an affected
  `<= 0.9.10` build. Treat the paste as a claim/version discrepancy, not as
  evidence that 1.0.0 is vulnerable.
- The advisory build recipe targets `example-junior-api`, which does not exist
  in the v0.9.10 archive. The harness uses a minimal public-API driver instead.
- The interrupted prior wake left a zero-length safe input after an assertion
  error, a wrong `psd.c:371` check and an empty CMake log. Those defects were
  corrected; no result from that attempt is claimed.
- The first allocator probe misdeclared `sail_malloc` as returning a pointer;
  its garbage status and unchanged guards are preserved in ignored evidence.
  The corrected wrapper uses the real `sail_status_t sail_malloc(size_t,
  void**)` ABI. No result from the broken probe is claimed.
- Rung 4 is LIMITED to chosen bytes at chosen offsets under a synthetic
  exact-size allocator. No production allocator adjacency, live application
  consumer, pointer control, indirect call, marker, command, network wire or
  side effect was observed. R5 is NOT claimed.
- Cheapest next experiment: scale the same PSD to width 64, height 8, depth 8.
  The vulnerable allocation becomes 64 bytes while the last row reaches
  offset 119 (56 bytes past); run the shipped SAIL CLI/plain glibc with safe
  and fixed controls and measure whether chosen bytes reach a live adjacent
  object. Preserve the current plain-small-input negative.
