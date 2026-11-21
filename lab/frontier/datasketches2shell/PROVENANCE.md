# Provenance — DataSketches HLL CouponList deserialization write (CVE-2026-103501)

All artifacts in `src/` were fetched read-only as provisioning on 2026-11-21
~12:46Z; nothing was sent to any external host. `run.sh` verifies every
SHA-256 with `sha256sum -c src/SHA256SUMS` before extracting or compiling;
pin drift exits 2. Raw source bytes, not rendered web readers, are authoritative
for line numbers.

| Pin | SHA-256 | Source |
| --- | --- | --- |
| `src/5.2.0.tar.gz` | `63e6bda660ee9730cc39746de87fd983118c28149e32ff9389fac98b27010a53` | <https://codeload.github.com/apache/datasketches-cpp/tar.gz/refs/tags/5.2.0> |
| `src/5.3.0.tar.gz` | `9b0800207dcc5cf631a098de0c2c30385235075adb91a211fb6156f353c345fb` | <https://codeload.github.com/apache/datasketches-cpp/tar.gz/refs/tags/5.3.0> |
| `src/cve103501.json` | `ed937165c9c2d5efa8ff2f25aee451fd6fd7a5fa33488436ff1ebbebbd2a660f` | <https://cveawg.mitre.org/api/cve/CVE-2026-103501> |
| `src/ghsa-w656-xfm5-jqjh.html` | `8242673d848d1665d847261291142f67141ae50e3f482e4e9962ceaea4c50f78` | <https://github.com/advisories/GHSA-w656-xfm5-jqjh> |
| `src/pr503.diff` | `a2c00afedc1ed1e7cfab5a2a6a65ec230e82c06f0887b35ffa722766e92fb201` | <https://github.com/apache/datasketches-cpp/pull/503.diff> |

Cross-checks: vendor advisory <https://lists.apache.org/thread/n2oc2j841dzsv4239jjp08of66bo79c5>;
release notes <https://github.com/apache/datasketches-cpp/releases/tag/5.3.0>;
oss-sec <https://seclists.org/oss-sec/2026/q4/125>. The GHSA HTML pin is a
snapshot, not byte-reproducible on re-fetch (GitHub rotates metadata IDs);
its advisory text is semantically identical on fresh GETs.

## Copied source and stand-ins

No library source is copied into the driver. `run.sh` extracts both pinned
release tarballs into the output directory and compiles `driver.cpp` against
the real `hll/include` and `common/include` headers of each tag with
`-fsanitize=address` where marked. The ASan and default-allocator paths call
the public `hll_sketch::deserialize(bytes, len)`; the ASan report names the
pinned library frames directly.

The only stand-in is `PageAlloc`, used by the `readback` and `guard` modes:
it supplies the eight-entry `uint32_t` coupon vector from a page-aligned
region so chosen bytes can be read after the library's own `memcpy`, or so
the first past-end store meets a `PROT_NONE` page. The write being measured
is always the library's `std::memcpy` at `CouponList-internal.hpp:116`, never
a harness copy. Seed sketches and the hostile buffer are generated with the
unmodified pinned 5.2.0 serialization API; only `LIST_COUNT_BYTE` (offset 6)
is changed from a valid count to the hostile count. `driver.cpp:83` first
copies the 16-byte valid seed header and two coupons into the buffer, so the
first 16 bytes are not chosen; every byte at offset 32 and beyond is the
caller's chosen value, which is the range the chosen-byte observations use.

## Pinned line numbers (raw bytes)

Affected tag 5.2.0:

- `hll/include/HllUtil.hpp:54` `LIST_COUNT_BYTE = 6`; `:59` `LIST_INT_ARR_START = 8`;
  `:90` `LG_INIT_LIST_SIZE = 3` (eight entries, 32 bytes).
- `hll/include/CouponList-internal.hpp:39` sizes `coupons_` to `1 << LG_INIT_LIST_SIZE`
  in LIST mode; `:101` reads `couponCount` from `data[6]`; `:102-104` computes
  expected length from that count but never checks capacity; `:110` allocates;
  `:116` `std::memcpy(sketch->coupons_.data(), data + 8, couponCount * 4)`.
- Stream path `:161` `numToRead = compact ? couponCount : coupons_.size()` and
  `:162` `read(is, coupons_.data(), numToRead * 4)` — same class, not exercised
  by this harness. Pinned `:155` is the `putOutOfOrderFlag` call and `:159` is
  a comment.
- Public caller chain: `HllSketchImplFactory.hpp:101` and
  `HllSketch-internal.hpp:63`.

Fixed tag 5.3.0: `CouponList-internal.hpp:102-108` rejects
`couponCount >= 8` before allocation in the byte path; the stream path has
the equivalent guard at `:156-163`; the surviving copy is at `:123`.
`pr503.diff` adds those two guards plus the two regression tests.

## Replay record

Direct run 2026-11-21 ~12:48Z: 11 PASS / 0 FAIL rc 0, two five-run groups both
`sha256=d7d0532239c8b926c23c102cac12b13ab9bae6506b7ff7f5341fd5aeda206e2a`.
Trace lines exclude ASan addresses, paths and PIDs; the readback line prints
offsets and byte values only.

A clean `git archive 818ec4a lab/frontier/datasketches2shell` extraction into
`/tmp/ds2-archive`, run with absolute outdir `/tmp/ds2-out-clean`, reproduced
11 PASS / 0 FAIL rc 0 and the same digest in both groups.

Independent witness replay (W71, 2026-11-21 ~12:56Z): clean
`git archive 434040d lab/frontier/datasketches2shell` into `/tmp/w71-ds-archive`,
`bash run.sh /tmp/w71-ds-out` -> 11 PASS / 0 FAIL rc 0 with the same digest in
both five-run groups; `pins.log` all five OK and fresh re-fetches byte-identical
for both release tarballs, the CVE JSON and the PR 503 diff. The GHSA HTML hash
differs on re-fetch but the normalized advisory text is identical (5671 chars),
confirming the snapshot caveat above. W71 found the stream-path citations
`:155`/`:159` wrong in raw 5.2.0 bytes and corrected here to `:161`/`:162`; no
code, grade or harness change resulted.
