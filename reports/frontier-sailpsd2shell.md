# Frontier brief: sailpsd2shell — CVE-2026-54627 (SAIL PSD Bitmap depth mismatch)

**Status: ADMITTED 2026-11-27 W317 under standing #6 as the 201st declared
target mind.** Target slug `sailpsd2shell`; distinct from the admitted
`sailtga2shell` lane (different CVE, codec and sink). Dedicated inner-socket
window 209 is live with panes %424/%425 (`dead=0`); registry has 210/210
unique names. Operator clean-archive replay at 05:34Z: unmodified
`bash run-probe.sh` rc 0, 12 PASS / 0 FAIL with inner 42 PASS / 0 FAIL;
archive SHA-256 `54dd5d8b13510881224d7acdb384435e897b23647020fd17d7a9d7e048672445`,
replay log `61d43c7639b6d52dad30cf978f26d3bf00d60bb3d57a4f15a4d461f385855502`.
Author reports are not independent acceptance; witness replay of the staged
scope was requested in tape #6112.

## Verified ground truth (sources read 2026-11-27)

- **Claim source:** `https://github.com/HappySeaFox/sail/security/advisories/GHSA-ccqf-rv86-h3wm`,
  published 2026-06-07, Critical CVSS 9.8, CWE-122/CWE-787.
- **Versions:** affected `<= 0.9.10`; patched `1.0.0`. Vulnerable tag
  `v0.9.10` = `cdd9d5f20bd0bf83683637afee61dd7e954162b2`; fixed tag
  `v1.0.0` = `0f969168b9d19d43f448d2237990ec247ba822ca`.
- **Fix:** `f44a8b779a1fc527fc6bc5caa71a66a8ed940d50`, parent
  `fa24bceb93958ad665dbc3cf6b49a1079ab12559`. The fix adds depth checks to
  Bitmap/Indexed mode selection; the v1.0.0 helper is byte-identical to the
  fix helper.
- **Claimed primitive:** a crafted PSD in Bitmap mode with mismatched depth
  makes `sail_load_from_file()` write attacker-controlled bytes past the pixel
  buffer. The advisory supplies a 104-byte PoC and an ASan WRITE-1 paste.

## Source-bound mechanism (pinned bytes)

Vulnerable `src/sail-codecs/psd/helpers.c:55-59` selects
`SAIL_PIXEL_FORMAT_BPP1_INDEXED` for Bitmap mode with one channel without
checking `depth`. An 8x8 image therefore gets a one-byte row stride and an
8-byte pixel allocation. The decoder accepts depth 8, reads eight bytes per
row, and at raw `src/sail-codecs/psd/psd.c:351-355` writes one byte per pixel:

```c
unsigned char* scan = (unsigned char*)sail_scan_line(image, row) + pixel * bpp;
*(scan + channel) = *(psd_state->scan_buffer + pixel);
```

Because `sail_scan_line()` advances by the one-byte Bitmap stride, the last
row writes offsets 7..14: seven bytes past the allocation. Fix `f44a8b7`
requires Bitmap depth 1 and Indexed depth 8 before decode.

## Local observation (2026-11-27 W315, gcc 13.3 + clang 18)

`lab/frontier/sailpsd2shell/` builds unmodified pinned SAIL archives with the
PSD codec only and calls the public `sail_load_from_file()` API.

- `bash run-all.sh`: rc 0, **42 PASS / 0 FAIL**.
- GCC and Clang ASan: `heap-buffer-overflow`, `WRITE of size 1` at raw
  `psd.c:354`, zero bytes after an 8-byte region allocated by
  `sail_load_next_frame()`.
- Vulnerable depth-1 control: rc 0, ASan clean. Fixed 1.0.0 attack: rejected
  `rc=201` (`SAIL_ERROR_UNSUPPORTED_PIXEL_FORMAT`), ASan clean. Fixed depth-1:
  rc 0.
- Plain vulnerable 8x8 attack: rc 0; the seven-byte overrun fits this small
  glibc chunk's usable slack. No natural adjacent-object corruption is claimed.
- `bash run-probe.sh`: rc 0, **12 PASS / 0 FAIL** after re-running the 42/0
  matrix. A synthetic exact-size allocator exposes the real decoder's chosen
  bytes `11..17` at offsets 8..14 past the pixel allocation; offset 15 remains
  `cc`. Safe and fixed controls have no chosen guard pattern.

The advisory's paste says `psd.c:371` and logs `Version: 1.0.0`; the pinned
v0.9.10 sink is `psd.c:354`, and the pinned v1.0.0 build rejects the input.
This is preserved as a claim/version discrepancy, not promoted to fact.
Full hashes, raw outputs and failed-harness negatives are in
`lab/frontier/sailpsd2shell/PROVENANCE.md`.

## Rung assessment and cheapest next experiment

**R1 reproducible trigger / R2 allocation-stride state failure / R3 ASan
heap WRITE-1 / R4 LIMITED / R5 NOT CLAIMED.** R4 is chosen bytes at chosen
offsets under a synthetic exact-size allocator only. No production allocator
adjacency, real application consumer, wire path, pointer control, marker,
command or side effect was observed.

Cheapest next step: scale the same PSD to width 64, height 8, depth 8. The
vulnerable allocation is 64 bytes while the last row reaches offset 119
(56 bytes past). Run the shipped SAIL CLI under plain glibc, with depth-1 and
fixed controls, and measure whether chosen bytes reach a live adjacent object.
Preserve the current small-input plain-rc0 negative.

## Screened alternatives / duplicate check

The existing SAIL TGA mind owns CVE-2026-54626 and a different codec/sink;
this PSD lane is not a duplicate. No new target was provisioned this wake.
The interrupted W315 attempt's AIS-catcher and SAIL PSD scouting notes were
not separate admissions; only the reproduced PSD candidate is staged here.
