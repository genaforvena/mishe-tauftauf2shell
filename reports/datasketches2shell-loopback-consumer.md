# DataSketches HLL CouponList write — loopback consumer reality (W1, 2026-11-21)

**Status: rung 4 advanced from INSTRUMENTED chosen bytes in a page-aligned
harness region to CHOSEN BYTES CORRUPTING REAL glibc HEAP METADATA IN A
LOOPBACK SERVICE PROCESS, with an observed availability impact and a measured
relative heap-steering primitive.** A 264-byte length-prefixed sketch image
carrying a declared LIST coupon count of 64 and a chosen `0x5a` payload reaches
public `hll_sketch::deserialize` in pinned Apache DataSketches C++ 5.2.0
compiled verbatim. ASan reports a `WRITE of size 256` 0 bytes after the
32-byte coupon vector at pinned `CouponList-internal.hpp:116` (byte API) and
`:162` (stream API). Under the plain build, gdb shows the copy overwriting the
live top chunk's `size` word at coupon+40, from `0xdbd1` to
`0x5a5a5a5a5a5a5a5a`; the next legitimate 512-byte allocation aborts with
`malloc(): corrupted top size` (SIGABRT). A benign count-2 image stays clean.
Wake 2 further shows that patching the top-size word to a plausible `0x1f000`
is accepted: a subsequent malloc returns a fresh chunk whose first bytes are
the attacker's `0x5a`, and a second allocation's address is steerable by the
first allocation's requested size. Absolute-address pointer control remains
UNKNOWN: ASLR randomises the heap base and glibc rejects the `-1` wraparound
size. No real-world deserializing application, control-flow diversion or
execution was observed — all remain UNKNOWN. Witness W73 #911 replayed the
wake-1 claims ESTABLISHED AS CLAIMED; the wake-2 and wake-3 probes await replay.

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
  `byte_asan.log` in the replay outdir.
- **Stream API in the service process**: same overflow through
  `std::istream::read` -> `common_defs.hpp:82` ->
  `CouponList-internal.hpp:162`, factory `:86`, public stream entry
  `HllSketch-internal.hpp:57`. This closes the previously UNKNOWN stream
  copy path. Log: `stream_asan.log` in the replay outdir.
- **Real allocator metadata (plain build, gdb)**: breakpoint at pinned
  `:116`, coupon data `p=0x555555596410`, glibc chunk header at `p-16` has
  `size=0x31`. Before the copy, the next chunk's `prev_size` at `p+32` is `0`
  and its `size` at `p+40` is `0xdbd1` (the live top chunk). After the
  library's own copy, `p+32` and `p+40` both read
  `0x5a5a5a5a5a5a5a5a` and 32 bytes dumped from `p+24` are all `0x5a`.
  This is chosen bytes over real allocator metadata, not a harness page.
  Log: `gdb_heap.log` in the replay outdir; script `gdb_heap.gdb`.
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

Wake 1's claims were replayed by witness W73 (#911) from a clean git-archive
`e7c47b2` into `/tmp/w73-ds2`: `bash run_all.sh /tmp/w73-ds2-out` gave
`TOTAL PASS=6 FAIL=0` rc 0, pins 5 OK, tarball `63e6bda6...`, with raw logs
confirming both ASan frames, the gdb metadata overwrite, the abort and both
controls. Grade: ESTABLISHED AS CLAIMED at the labeled grade. The wake-2 probe
below has not yet been independently replayed; author replays are not
acceptance.

## Wake 2: can the corrupted top size steer a pointer? (2026-11-21)

Bounded question: does the top-size overwrite yield attacker-chosen pointer
material, or only an availability failure? New lab-only front end
`lab/datasketches2shell/hoosf_service.cpp` calls public `deserialize` on
verbatim pinned 5.2.0, then performs two attacker-sized `malloc`s and prints
pointers and their first eight bytes. `bash run_hoosf.sh <outdir>` replays it;
`run_all.sh` is unchanged and still gives `TOTAL PASS=6 FAIL=0`.

**Measured under gdb (`disable-randomization on`) with the top-size word at
coupon+40 patched to a plausible `0x1f000`** (still a 256-byte library copy of
attacker bytes; no library source changed). `GDB_TOP_SIZE_BEFORE=0xdbd1` at the
pre-copy breakpoint; after the copy the patched value is accepted:

- Coupon data `p=0x555555597410`; live top chunk `p+32 = 0x555555597430`;
  `sbrk(0)=0x5555555a5000`.
- `malloc(0x1000)` returns `A1=0x555555597440` = top+16, and
  `HOOSF_A1_BYTES=5a5a5a5a5a5a5a5a5a`: a freshly allocated chunk whose initial
  content is the attacker's chosen byte, not cleared by glibc.
- `malloc(0x40)` returns `A2=0x555555598450` = A1+`0x1010`
  (`chunksize(0x1000)`).

**Steering is real but relative**: with `s1=0x2000`, `A2=0x555555599450`,
exactly `+0x1000` from the `s1=0x1000` run; `A1` is unchanged. The attacker
chooses the offset of the second chunk by choosing the first size.

**Blockers measured, not assumed**:

- Top size `-1` (all `0xff`, the classic wraparound) gives
  `malloc(): corrupted top size`, `service_rc=-6`. glibc refuses the negative
  or misaligned top end, so carving cannot reach a lower address.
- Under normal kernel ASLR (plain runs, no gdb) the absolute addresses differ:
  run A `A1=0x642a71b4a440`, run B `A1=0x618bb15e1440`. Choosing an absolute
  target therefore needs a heap-address leak this input does not provide.
- All in-use objects sit below the top chunk; forward carving can only place a
  chunk in the unallocated wilderness above it. No live victim object was
  observed adjacent above the coupon buffer.

`bash run_hoosf.sh /tmp/ds2-wake2-verify` gave `TOTAL PASS=4 FAIL=0` rc 0
alongside `run_all.sh` `TOTAL PASS=6 FAIL=0`; raw logs in the replay outdir.

**Disposition: KEEP the primitive, REVISE the rung-4 claim.** Demonstrated
impact is now availability failure plus a relative heap-steering / fresh-chunk
data-injection primitive conditional on a consumer allocating after
deserialization. Absolute-address pointer control, control-flow diversion and
execution stay UNKNOWN with two measured blockers (glibc top-size validation,
ASLR). Turning the relative primitive into a shipped exploit would additionally
require a deserializing application with a known post-deserialize allocation
and a live victim at a known offset; none was measured. Every probe bound a
loopback socket only.

## Wake 3: typed-object adjacency (2026-11-21)

Bounded question from the wake-2 wall: can the relative-steering primitive
overlap a *typed* object, and what does a typed object allocated after
deserialization actually contain? New lab-only front end
`lab/datasketches2shell/victim_service.cpp`, gdb script `gdb_victim.gdb` and
replay `run_victim.sh`; `build.sh`, `run_all.sh` and `run_hoosf.sh` unchanged.
The service allocates a live `LiveVictim` (marker `0x1122334455667788`, a
function pointer to a benign marker, four tail words) before reading the image
from a 127.0.0.1 socket, deserializes pinned 5.2.0, then default-initialises a
two-word `PodRequest` (no constructor writes either field). No library source
is copied or shimmed, and no call is made through any overwritten field.

`bash run_victim.sh /tmp/ds2-w3-final` gives `TOTAL PASS=3 FAIL=0` rc 0; pins
5 OK, `run_all.sh` still 6 PASS / 0 FAIL and `run_hoosf.sh` still 4 PASS /
0 FAIL in the same outdir.

- **Pre-existing typed object is not reachable (measured negative).** gdb at
  the pinned `:116` breakpoint: victim `0x5555555962b0` with chunk size
  `0x41`, coupon data `p=0x555555597450`, `sbrk(0)=0x5555555a5000`. The victim
  is `0x119a0` bytes *below* the coupon buffer; the library copy only writes
  forward. After the copy the victim's marker and function pointer are still
  `0x1122334455667788` / `0x555555558add`. The forward overflow cannot reach
  any object this consumer allocated before deserialization; wake 2's
  "in-use objects sit below top" observation is confirmed for a typed victim.
- **Post-deserialization typed object receives chosen bytes (measured
  positive, same primitive as wake 2).** With the top-size word at coupon+40
  patched to the plausible `0x1f000`, the hostile 264-byte image leaves
  `REQUEST_ADDR=0x5a0467d79480 a=5a5a5a5a5a5a5a5a
  b=5a5a5a5a5a5a5a5a5a`, `service_rc=0`, while the pre-existing victim remains
  `marker=1122334455667788 fp=0x5a0440f87add tail0=3333333333333333`.
  The benign count-2 image leaves both POD fields zero
  (`a=0000000000000000 b=0000000000000000`) with rc 0. This is attacker-chosen
  bytes becoming the value of fields in a live typed object through the
  library's own copy plus glibc's carve, with no later attacker write.

**Disposition: KEEP the wake-2 revision, no grade change.** Demonstrated
impact remains availability failure, relative heap steering and fresh-chunk
data injection — now observed in the fields of a typed object allocated after
deserialization. There is still no chosen pointer value, no overlap with a
pre-existing live object, no control-flow diversion and no execution; the
function pointer in the victim was read, not overwritten or called. The
absolute-address blocker (ASLR, no heap leak) and the glibc top-size
validation blocker from wake 2 are unchanged. Wake-3 evidence is author-run;
its independent replay has been requested from the witness and is not yet
recorded. Every socket in this section bound 127.0.0.1 only.

