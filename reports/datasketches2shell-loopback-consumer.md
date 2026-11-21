# DataSketches HLL CouponList write — loopback consumer reality (W1, 2026-11-21)

**Status: rung 4 advanced from INSTRUMENTED chosen bytes in a page-aligned
harness region to CHOSEN BYTES CORRUPTING REAL glibc HEAP METADATA IN A
LOOPBACK SERVICE PROCESS, with an observed availability impact.** A 264-byte
length-prefixed sketch image carrying a declared LIST coupon count of 64 and a
chosen `0x5a` payload reaches public `hll_sketch::deserialize` in pinned
Apache DataSketches C++ 5.2.0 compiled verbatim. ASan reports a `WRITE of size
256` 0 bytes after the 32-byte coupon vector at pinned
`CouponList-internal.hpp:116` (byte API) and `:162` (stream API). Under the
plain (non-ASan) build, gdb shows the copy overwriting the live top chunk's
`size` word at coupon+40, from `0xdbd1` to `0x5a5a5a5a5a5a5a5a`; the next
legitimate 512-byte allocation in that process aborts with `malloc():
corrupted top size` (SIGABRT). A benign count-2 image stays clean. No
real-world deserializing application, pointer control, control-flow diversion
or execution was observed — all remain UNKNOWN. Witness replay is requested
and not yet returned.

This extends `reports/frontier-datasketches2shell.md`; the claim and pins are
`lab/frontier/datasketches2shell/PROVENANCE.md`, witness W71 #889.

## Repro

Everything durable is under `lab/datasketches2shell/`; no library source is
copied, patched or shimmed. `build.sh` re-verifies all five pins with
`sha256sum -c` before extracting the pinned 5.2.0 tarball.

```
cd lab/datasketches2shell
bash run_all.sh /tmp/ds2-wake1-verify
# TOTAL PASS=6 FAIL=0 / ALL_CHECKS_PASS / rc 0
```

`drive.py` starts each service as its own child, waits for `SERVICE_LISTEN`,
and connects only to the 127.0.0.1 port that child bound. The image is built
from a genuine 5.2.0 `serialize_compact()` seed (16 bytes, two updates); only
wire byte 6 (the coupon count) and the payload bytes are changed. Count 64
gives `8 + 64*4 = 264` bytes. `service.cpp` exercises the byte-buffer API,
`stream_service.cpp` the `std::istream` API. The `postalloc` mode makes one
legitimate 512-byte allocation immediately after deserialization returns and
the sketch has been destroyed.

## Observed evidence

- **Byte API in the service process**: ASan `heap-buffer-overflow`, `WRITE of
  size 256`, 0 bytes after a 32-byte region. Frames:
  `CouponList-internal.hpp:116` -> `HllSketchImplFactory.hpp:101` ->
  `HllSketch-internal.hpp:63` -> `service.cpp:68`. The allocation stack names
  the coupon vector from `CouponList-internal.hpp:39`/`:110`. Log:
  `lab/datasketches2shell/out/byte_asan.log`.
- **Stream API in the service process**: same overflow through
  `std::istream::read` -> `common_defs.hpp:82` ->
  `CouponList-internal.hpp:162`, factory `:86`, public stream entry
  `HllSketch-internal.hpp:57`. This closes the previously UNKNOWN stream
  copy path. Log: `out/stream_asan.log`.
- **Real allocator metadata (plain build, gdb)**: breakpoint at pinned
  `:116`, coupon data `p=0x555555596410`, glibc chunk header at `p-16` has
  `size=0x31`. Before the copy, the next chunk's `prev_size` at `p+32` is `0`
  and its `size` at `p+40` is `0xdbd1` (the live top chunk). After the
  library's own copy, `p+32` and `p+40` both read
  `0x5a5a5a5a5a5a5a5a` and 32 bytes dumped from `p+24` are all `0x5a`.
  This is chosen bytes over real allocator metadata, not a harness page.
  Log: `out/gdb_heap.log`; script `gdb_heap.gdb`.
- **Observed consequence**: hostile count 64, `SERVICE_DESERIALIZE
  rv=ok estimate=64.000010` followed by `malloc(): corrupted top size`,
  `service_rc=-6`. Benign count 2: `SERVICE_POSTALLOC ok byte=11`,
  `SERVICE_EXIT`, `service_rc=0`. Logs: `out/postalloc_64.log`,
  `out/postalloc_2.log`.

- **Causal control**: the same count-64 image with only the eight bytes at
  coupon+40 restored to the observed original top-size word `0xdbd1` keeps
  the full 256-byte overflow but removes the abort:
  `SERVICE_POSTALLOC ok byte=11`, `SERVICE_EXIT`, `service_rc=0`
  (`out/postalloc_restored.log`). The abort is therefore caused by the chosen
  bytes at coupon+40, not by the overflow elsewhere.

## Interpretation and limits

The corrupted word is the top chunk's size field, so the immediate durable
effect is an availability failure on the next allocation, not a pointer value
we control. glibc's free of a 32-byte chunk takes the fastbin path, which does
not consolidate with the top chunk; that is why the abort surfaces at the next
malloc rather than at sketch destruction. Turning the corrupted top size into
pointer control would need a House-of-Force-style sequence with known heap
addresses and a chosen victim object — not measured here, so it stays UNKNOWN.
This lab service is a minimal consumer, not a shipped application; which real
applications deserialize untrusted HLL images and what heap layout they have
also stay UNKNOWN. Every run bound a loopback socket only; no public host was
contacted. `run_all.sh` is a lab replay script, not a test of a shipped
consumer.

Witness replay of this report's claims was requested on the chat tape and is
not yet returned. Author replays are not independent acceptance.
