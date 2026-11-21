# Frontier brief — DataSketches HLL CouponList deserialization write (DataSketches2Shell)

**Status: new frontier find, brief + harness COMPLETE (2026-11-21 ~12:49Z) —
independent witness replay W71 ESTABLISHED AS CLAIMED at this grade; operator
admission pending.** Rung 3 is ESTABLISHED under ASan against the real,
verbatim-pinned upstream library; rungs 1/2 are ESTABLISHED on the same pinned
library built without sanitizers. Rung 4 shows attacker-chosen bytes at chosen
offsets past the 32-byte coupon buffer through the library's own `memcpy` and
public `deserialize` entry point. No deserializing application, network
listener, real heap neighbour object, pointer, control-flow diversion or
execution was observed — all stay UNKNOWN. The advisory's "potentially enabling
further exploitation" is a claim, not a lab result.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-103501 / GHSA-w656-xfm5-jqjh; CNA Apache Software
  Foundation, reporter anonymous. CVE published `2026-10-10T10:22:55.843Z`,
  updated `2026-10-16T15:22:14.055Z`. CWE-122 (heap buffer overflow) and
  CWE-1284 (improper validation of specified quantity in input). CNA's own
  severity text is **moderate**; CISA ADP assigns CVSS 3.1
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 CRITICAL**, and the GitHub
  advisory page repeats Critical/9.8. Record all three rather than collapsing
  them. Verbatim CNA description: "When deserializing a sketch in LIST mode,
  from either a byte buffer or a stream, the coupon count was read from the
  input and used as the number of entries to copy into a fixed buffer of 8
  entries, without checking it against the buffer's capacity. A crafted sketch
  could cause a write of up to 988 bytes past the end of this internal heap
  buffer."
- **Affected/fixed**: Apache DataSketches C++ `1.0.0-incubating` through
  `5.2.0` (CVE `lessThanOrEqual 5.2.0`); fixed in `5.3.0`. Release notes list
  this as one of five deserialization security fixes (release-notes bullet:
  "HLL CouponList validates the coupon count"). Fix is PR #503, whose GitHub
  API title is "Fix CouponList deserialization count validation bug"; it adds
  a capacity guard to both the byte-buffer and stream constructors and two
  regression tests.
- **Pins**: `src/cve103501.json`, `src/ghsa-w656-xfm5-jqjh.html`,
  `src/pr503.diff`, and the full `5.2.0` / `5.3.0` release tarballs — five
  SHA-256 pins in `lab/frontier/datasketches2shell/PROVENANCE.md`. The GHSA
  HTML is a snapshot (GitHub rotates metadata IDs on fresh GETs).
- **This lab**: the pinned upstream headers are compiled verbatim with ASan;
  the driver changes only the serialized count byte and payload values. ASan
  reports a `WRITE of size 256` at pinned
  `CouponList-internal.hpp:116`, called from the public
  `hll_sketch::deserialize`. Values `0x5a`, `0xa5` and `0x77` are read back at
  offsets +32/+48/+64/+96/+128/+224/+255; a `PROT_NONE` guard page faults at
  the first past-end store; `5.3.0` rejects the same bytes before copying.

## Source-bound mechanism

Line numbers are from raw bytes in the pinned tarballs, tag `5.2.0` unless
marked fixed.

1. `HllUtil.hpp:54` puts the LIST coupon count at wire byte 6, `:59` puts the
   coupon array at byte 8, and `:90` sets `LG_INIT_LIST_SIZE = 3`.
   `CouponList-internal.hpp:39` therefore allocates eight `uint32_t` entries
   — 32 bytes — for the LIST coupon vector.
2. `newList(const void*, size_t, const A&)` reads `couponCount` from
   `data[6]` at `:101`. `:102-104` derives an expected input length from that
   count and checks only the *input* length, never the destination capacity.
3. `:116` executes
   `std::memcpy(sketch->coupons_.data(), data + 8, couponCount * 4)`. The
   count is one attacker-controlled byte (up to 255) and the source bytes are
   the rest of the attacker's sketch image, so both the length and the copied
   bytes are chosen. A count of 64 copies 256 bytes into the 32-byte vector;
   a count of 255 copies 1020 bytes, 988 past it — the advisory's number.
4. The public path is real: `HllSketchImplFactory.hpp:101` dispatches a
   `LIST_PREINTS` image to `CouponList::newList`, reached from
   `HllSketch-internal.hpp:63` (`hll_sketch::deserialize(bytes, len)`).
5. The stream overload has the same defect at `:161`/`:162`: `:161` sets
   `numToRead = compact ? couponCount : coupons_.size()` and `:162` executes
   `read(is, coupons_.data(), numToRead * 4)`. It is source-bound but **not
   exercised** here. Pinned `:155` is the `putOutOfOrderFlag` call and `:159`
   is a comment.
6. Fixed `5.3.0`: `CouponList-internal.hpp:102-108` rejects
   `couponCount >= 8` before allocation in the byte path (guard at `:156-163`
   in the stream path); the surviving copy is at `:123`. Both regression
   tests in `pr503.diff` use `couponCount = capacity` and expect
   `std::invalid_argument`.

## Lab evidence

`cd lab/frontier/datasketches2shell && bash run.sh <outdir>`:

- 11 PASS / 0 FAIL, exit 0. Two independent five-run groups both
  `sha256=d7d0532239c8b926c23c102cac12b13ab9bae6506b7ff7f5341fd5aeda206e2a`.
- Rung 1: a real valid `5.2.0` compact sketch is serialized by the library,
  then only byte 6 is changed to 64 and the payload filled with the chosen
  value. The public deserialize accepts it.
- Rung 2: 256 bytes land in a 32-byte heap vector; the declared count drives
  the copy length with no capacity check.
- Rung 3 (ASan): `heap-buffer-overflow`, `WRITE of size 256`, 0 bytes after a
  32-byte region, frames `CouponList-internal.hpp:116` →
  `HllSketchImplFactory.hpp:101` → `HllSketch-internal.hpp:63`. With count 255
  the report is `WRITE of size 1020` against the same 32-byte region.
- Rung 4 (INSTRUMENTED chosen-byte control): with a page-aligned destination
  supplied by the harness allocator, `0x5a`, `0xa5` and `0x77` each read back
  at offsets +32/+48/+64/+96/+128/+224/+255 after the library's own `memcpy`.
  A guard page immediately after the 32-byte region faults with rc 139 at the
  first past-end store.
- Negative controls: fixed `5.3.0` throws "Attempt to deserialize invalid
  CouponList with couponCount >= capacity. Found couponCount: 64, capacity: 8"
  with no ASan report; vulnerable count 2 and fixed count 2 are ASan-clean.

**Harness boundary, stated plainly**: the ASan run uses the library's real
default allocator and reports the upstream copy directly — no shim performs
the write. For chosen-byte observation and guard-page proof, the destination
vector is placed in page-aligned memory by a harness allocator; that changes
where the bytes land, not the library code that writes them. No sketch
serializer was modified, no network/deserializing application ran, and no
adjacent real object was corrupted. Trace lines exclude ASan PID, address and
path text.

## Rung-4 feasibility assessment

This is an attacker-controlled-length, attacker-controlled-content heap write
through a real public deserialization API, with the fix hunk and affected
bytes both pinned. The remaining gap to unqualified rung 4 is the consumer:
which applications deserialize untrusted HLL images, their allocator and heap
layout, and whether chosen bytes can reach an object header, pointer or
function pointer. None of that was measured here.

**Cheapest rung-raising experiment**: write a loopback-only service that reads
a length-prefixed sketch image from a local socket, calls
`hll_sketch::deserialize(buf, len)` from pinned `5.2.0`, and run it under ASan
and gdb. Send the 264-byte count-64 image; expect the ASan WRITE at
`CouponList-internal.hpp:116` inside the service process. Then freeze the
first past-end bytes, inspect the real heap neighbour under gdb, and only then
attempt pointer/metadata control. The stream overload deserves a second
harness (`deserialize(std::istream&)`) because its copy path differs. This
belongs to a dedicated target mind after admission, not this extracted-driver
lane.

## Scope and boundaries

Loopback-free local process drivers: no socket, server, deserializing
application or external probe. Sources were fetched read-only as
provisioning. Harness stand-ins and exact copied ranges are enumerated in
`PROVENANCE.md`. No nginx or other plant's lane was touched.
