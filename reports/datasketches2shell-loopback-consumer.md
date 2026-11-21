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
first allocation's requested size. Wake 4 further shows that, under disclosed
lab conditions (synthetic loopback consumer, consumer-side tcache grooming,
`-no-pie` build carrying a stable marker address in the image), the pinned
copy can overwrite a live object's function pointer with an image-chosen
address and an indirect call through that field reaches a *different* benign
marker; a benign count-2 control reaches the original marker. Wake 6 found
one shipped deserializing consumer (the DataSketches PostgreSQL extension),
measured the same pinned write inside it under both stock and assertion
builds, and observed no failure there. ASLR-resistant pointer control and
execution of attacker-chosen code remain UNKNOWN.

Wake 8 adds a second real-consumer measurement: the upstream DataSketches
Python 5.2.0 binding, compiled verbatim into a CPython extension against the
pinned 5.2.0 headers, uses glibc `operator new` for the coupon vector. There a
count-18 image corrupts adjacent glibc chunk metadata and the process aborts
at interpreter shutdown with `corrupted size vs. prev_size`; fixed 5.3.0
rejects the same image. No pointer value, control-flow diversion or
attacker-chosen code was observed there either.

Wake 9 adds a socket-free stream-overload replay with chosen-byte readback, a
guard-page fault and a compact-flag causal control for the stream copy at
pinned `:162`; fixed 5.3.0 rejects the same image. No grade change and no new
real-consumer claim.

Witness W73 (#911) replayed the wake-1 claims ESTABLISHED AS CLAIMED; witness
W74 replayed the wake-2 (#922) and wake-3 (#929) claims from clean git archives
of `b95653e` and `e6e8b86`, also ESTABLISHED AS CLAIMED at their labeled grades
(6+4 PASS and 3 PASS rc 0, five pins OK). Witness W75 replayed wake 4 (#951)
from a clean git archive of `fa551e9`, ESTABLISHED AS CLAIMED at the
lab-build-only grade (4 PASS rc 0, five pins OK). The witness verdict on wake 6
(#970) replayed `cc9ba4d` + `aa9ebe8` from a clean archive and also found
ESTABLISHED AS CLAIMED at the bounded-negative, real-consumer grade; see the
final section for its evidence and the two NITs it raised.
Wake 8 has no independent replay yet; its grade is author-observed only until
a witness checks it.

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
controls. Grade: ESTABLISHED AS CLAIMED at the labeled grade. The wake-2 and
wake-3 probes below were independently replayed by witness W74 (see the final
sections); author replays were not accepted as verdicts.

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
Witness W74 independently replayed commit `b95653e` from a clean git archive
into `/tmp/w74-ds2` (build first, then `run_hoosf.sh`): 6 PASS plus 4 PASS rc 0,
five pins OK, A1=`top+16` with eight chosen bytes, A2=`A1+0x1010`, a `+0x1000`
request shifting A2 by exactly `+0x1000`, `-1` top size aborting rc -6 and
different ASLR runs giving different A1 — ESTABLISHED AS CLAIMED, bounded
relative steering only.

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
validation blocker from wake 2 are unchanged. Witness W74 independently
replayed commit `e6e8b86` from a clean git archive into `/tmp/w74-ds3`:
`run_victim.sh` 3 PASS rc 0, victim below coupon below sbrk, marker and
function pointer unchanged, hostile `PodRequest` reading eight chosen bytes
per field with the victim intact and benign fields zero — ESTABLISHED AS
CLAIMED, no call, pointer or control-flow claim accepted. Every socket in
this section bound 127.0.0.1 only.

## Wake 4: tcache-groomed live function pointer (2026-11-21)

Bounded question, unlocked by the W74 verdicts above: can consumer-side
glibc `tcache` grooming put a live object with a function-pointer field
immediately above the coupon vector, so that the library's own copy at pinned
`CouponList-internal.hpp:116` overwrites that pointer with image-chosen bytes
and an indirect call through the field reaches a chosen target? This applies
the same precondition the witness accepted in the hnswlib2shell lane
(`reports/hnswlib2shell-live-object.md`, commit `2a271d3`) to this primitive.

**Conditions, disclosed up front.** Lab-only synthetic loopback consumer
(`lab/datasketches2shell/groom_service.cpp`), built `-no-pie -O0` so two
distinct benign marker addresses are stable and can be carried in the image;
consumer performs ordinary `malloc`/`new`/`free` grooming before deserialize;
no malloc interposer, no library source copied or patched; one 127.0.0.1
listener. No real deserializing application, no off-loopback contact, no
ASLR-defeating leak and no execution beyond the benign markers.

**Layout and write.** The consumer first allocates `G = malloc(32)` (same size
class as the eight-`uint32_t` coupon vector), then a `LiveVictim` with
`{magic, callback, refcount, label[32]}`, then `free(G)` so `tcache[0x30]`
points at `G`. The coupon vector's own `malloc(32)` inside deserialize reuses
`G`, placing the live victim's chunk header at coupon+40 and its fields at
coupon+48. A LIST image with count 18 makes `:116` copy 72 bytes: 32 in-vector
plus 40 OOB bytes that cover the victim's chunk size, magic, callback and
refcount, and stop before the sketch object at coupon+96. The crafted bytes
preserve the victim's chunk size (`0x41`, so it stays a live chunk) and set
magic `0x1111111111111111`, callback to `benign_marker3` (a different function
from the original `benign_marker2`) and refcount `0x3333333333333333`.

**Observation.** `bash lab/datasketches2shell/run_groom.sh <abs-outdir>` gives
`TOTAL PASS=4 FAIL=0` rc 0 with five pins verified by `build.sh`:

- gdb frozen at pinned `:116`: `GDB_P=...320 == GDB_G`, `GDB_DELTA_V=48`,
  victim chunk size `0x41` before and after, callback `0x403b4a` ->
  `0x403b84`, magic and refcount read back as chosen.
- Plain hostile run: `AFTER_WRITE V_magic=1111111111111111 V_cb=0x403b84
  V_ref=3333333333333333`, `BENIGN_MARKER3_EXECUTED`, `CALL_THROUGH
  ptr=0x403b84 m3=3333333333333333`, `service_rc=0`. The call is a genuine
  indirect call through the memory field the library wrote, not a comparison
  or a re-store of the original value.
- Benign count-2 control: victim unchanged, the original pointer reaches
  `BENIGN_MARKER2_EXECUTED`, `service_rc=0`.
- ASan on the same count-18 image: `WRITE of size 72`, 0 bytes after the
  32-byte coupon region, frame `CouponList-internal.hpp:116` through public
  `HllSketch-internal.hpp:63`.

Five fresh output directories gave identical marker identity, chosen fields
and `TOTAL PASS=4 FAIL=0`; only the heap base varied with ASLR. `run_all.sh`
still gives `TOTAL PASS=6 FAIL=0`.

**Failed layouts preserved (not retried into a pass).** With count 64 (the
256-byte copy) the plain service died `service_rc=-11` before the marker call:
the copy also reached the sketch object above the victim. A pre-warm benign
deserialize reversed the physical order (victim below `G`) and broke the
grooming; both were reverted rather than claimed. Reducing the copy to 72
bytes was the bounded repair that kept the victim reachable and the sketch
object intact.

**Disposition: grade advanced for the lab build, not for the real world.**
Rung 4 is now *demonstrated security impact in a lab build*: attacker-chosen
bytes in a live object's function-pointer field and an observed indirect-call
diversion to a different benign marker, with a clean benign control. The
advance is conditional on consumer-side grooming and a non-PIE image carrying
a stable address. Absolute pointer control without those conditions, real
application reachability, and execution of attacker-chosen code remain
UNKNOWN. Witness W75 independently replayed commit `fa551e9` from a clean git
archive into `/tmp/w75-ds4` (the archive must include
`lab/frontier/datasketches2shell`, which `build.sh` needs for the five pins):
`build.sh` verified five pins, `run_groom.sh` 4 PASS / 0 FAIL rc 0 and
`run_all.sh` 6 PASS / 0 FAIL. gdb at pinned `:116` showed p=G=0x442320,
V=p+48, victim chunk `0x41` before and after, callback `0x403b4a` ->
`0x403b84` with chosen magic and refcount; the plain hostile image reached
`BENIGN_MARKER3_EXECUTED` with `m3=3333333333333333`, the benign count-2
control reached the original marker; 5/5 fresh archives were identical.
Two witness counterexamples were checked and the claim held: re-patching the
same image's callback bytes back to marker2 `0x403b4a` while keeping the chosen
magic/refcount executed marker2 with `m2=2222222222222222`, so the pointer is
image-carried rather than a fixed consequence of grooming; and gdb at
main+1068 showed `call *%rax` with `rax=0x403b84`, a genuine indirect call
through the written field with no re-store in `groom_service.cpp`. Grade:
ESTABLISHED AS CLAIMED at the lab-build-only grade, with the bounds above
retained. Every socket in this section bound 127.0.0.1 only.


## Wake 6: a real deserializing consumer, measured (2026-11-21)

The previously UNKNOWN question "which applications deserialize untrusted
HLL images" now has one concrete, shipped answer: the Apache DataSketches
PostgreSQL extension.
In the pinned extension source (commit `56d871276d32a1235041b553559143a9697f8906`,
`src/hll_sketch_pg_functions.c` sha256 `710709d1f62e5979e77799222128e4630f62f5046bdd20ae14e323d9bc99ea7b`),
`hll_sketch_deserialize` is called on client-supplied `bytea` at `:161`, `:338`,
`:350`, `:369`, `:385`, `:412` and `:418`; `pg_hll_sketch_get_estimate` starts
at `:345` and deserializes at `:350`. `sql/datasketches_hll_sketch.sql` defines
`hll_sketch_in(cstring)` and `CREATE CAST (bytea as hll_sketch)`, so a base64
client literal is a deserialization input. The extension instantiates
`hll_sketch_alloc<palloc_allocator<char>>` (`src/allocator.h`), i.e. its
allocations come from PostgreSQL memory contexts, **not** glibc malloc.

Sources and hashes are in `lab/datasketches2shell-pg/PROVENANCE.md` and
`SHA256SUMS`. `bash lab/datasketches2shell-pg/run.sh <outdir>` rebuilds if
needed, starts a loopback-only PostgreSQL 16.4 instance, creates a fresh
database, loads the extension's verbatim HLL SQL, sends four images through
`hll_sketch_get_estimate`, and stops the server on exit. The extension's HLL
objects are built from verbatim source against the pinned, unmodified 5.2.0
headers; unrelated sketch families are omitted only to avoid Boost headers.

Observed (`/tmp/ds2-pg-replay2`, rc 0):

- benign 16-byte genuine seed: `PG_DS2_BENIGN 2.000000004967054`;
- count 18 (80 bytes): `PG_DS2_C18 18.00000075995926`;
- count 64 (264 bytes): `PG_DS2_C64 64.00001001358214`;
- count 255 (1028 bytes): `PG_DS2_C255 255.00016085815176`.

All four queries returned normally and a follow-up `select 1` succeeded. A
second build with `--enable-cassert` (MEMORY_CONTEXT_CHECKING) on a separate
loopback port gave the same four estimates, no warning and a live server.

gdb on a single-user backend confirmed the same library copy inside the real
consumer: breakpoint at pinned `CouponList-internal.hpp:116` in
`CouponList<palloc_allocator<char>>::newList`, `count=64`, coupon data
`p=0x5555562d70f0`. In the stock build the words at `p+32` and `p+40` were
`0` before the library's `memcpy` and `0x5a5a5a5a5a5a5a5a` after; in the
assertion build (`p=0x5555563b18c8`) the memory-context sentinel at `p+32`
was `0x7f7f7f7f7f7f7f7f` before and `0x5a5a5a5a5a5a5a5a` after. Both raw
logs are in `lab/datasketches2shell-pg/gdb_pg.log` and `gdb_pg_assert.log`.
So chosen bytes do overwrite real allocator state in a shipped consumer,
but no crash, abort, pointer value or diverted call was observed.

**Fixed-version causal control in the same consumer.** Rebuilding the same
verbatim extension objects against the pinned, unmodified 5.3.0 headers
changes only that image's fate: the benign seed still returns
`PG_DS2_BENIGN 2.000000004967054`, while the count-64 image is rejected before
the copy with `ERROR: Attempt to deserialize invalid CouponList with
couponCount >= capacity. Found couponCount: 64, capacity: 8` and the server
stays alive. The 5.2.0 build was restored afterwards; `run.sh` uses 5.2.0.

The absence of a sentinel warning has a source-level reason, preserved as a
negative: `AllocSetFree` checks the trailing sentinel only for external
single-chunk blocks (`src/backend/utils/mmgr/aset.c:1008-1027`); a 32-byte
coupon vector is an ordinary chunk in a block, and a context reset does not
check per-chunk sentinels. The glibc top-size steering and tcache grooming of
wakes 2-4 do not transfer to this consumer because it uses `palloc`.

**Disposition: KEEP the lab-build grade, do not advance the shipped-app grade.**
The real-consumer item moves from UNKNOWN to "identified and measured": a
client-reachable deserialization path exists in the PostgreSQL extension and
the pinned write occurs there, but with no observed impact beyond chosen
bytes in allocator slack. Real applications with a glibc allocator, a live
victim at a known offset, an address leak and natural call-through remain
UNKNOWN. Every socket in this section bound 127.0.0.1 only; no probe left the
loopback host.

**Witness replay (#970): ESTABLISHED AS CLAIMED at the bounded-negative,
real-consumer grade.** The witness replayed `cc9ba4d` + `aa9ebe8` from a clean
git archive of `aa9ebe8` containing `lab/datasketches2shell-pg` and
`lab/frontier/datasketches2shell`, copying in the two pinned gitignored
PostgreSQL tarballs: 2/2 PG pins and 5/5 library pins verified. Its own fresh
PostgreSQL 16.4 plus verbatim extension HLL build against pinned 5.2.0 gave
`run.sh` rc 0, benign `2.000000004967054`, c18 `18.00000075995926`, c64
`64.00001001358214`, c255 `255.00016085815176`, with the server alive. gdb on
a single-user backend hit pinned `CouponList-internal.hpp:116` with `count=64`,
`p=0x5555562d7060`, words at `p+32`/`p+40` going `0` ->
`0x5a5a5a5a5a5a5a5a`, and backtrace `newList:119` <-
`HllSketchImplFactory.hpp:101` <- `HllSketch-internal.hpp:63` <-
`hll_sketch_c_adapter.cpp:119` <- `pg_hll_sketch_get_estimate` at
`hll_sketch_pg_functions.c:350`. Its counterexample held: changing only the
wire payload byte to `0x3c` changed both words to `0x3c3c3c3c3c3c3c3c`, so the
bytes are wire-carried, not a gdb artifact. A rebuilt 5.3.0 rejected c18/c64/
c255 with `couponCount >= capacity. Found couponCount: 64, capacity: 8` while
benign still returned `2.000000004967054`; 5.2.0 was restored and all four
estimates reconfirmed. An independent `--enable-cassert` build gave the same
four estimates, no warning or error in the server log, and gdb sentinel words
at `p+32`/`p+40` going `0x7f7f7f7f7f7f7f7f` -> `0x5a5a5a5a5a5a5a5a`. No crash,
abort, pointer value, diverted call or shipped-app impact was observed or
claimed.

Two witness NITs are fixed here: the deserialization call-site citations now
name the verified lines in the pinned `hll_sketch_pg_functions.c` (sha
`710709d1...`), and `lab/datasketches2shell-pg/gdb_pg.gdb` no longer hardcodes
lab absolute paths. For a clean-archive gdb replay set `DS2_PG_HOME` to the
archive's `lab/datasketches2shell-pg` directory before sourcing the script;
it supplies both the header directory and `PGDATA`.


## Wake 8: a glibc-allocator Python consumer, measured (2026-11-21)

Bounded question: wake 6's PostgreSQL consumer uses `palloc`, so the glibc
metadata overwrite and tcache grooming of wakes 1-4 need not transfer. Does
the pinned write corrupt an ordinary glibc-allocator consumer built from a
shipped binding? Apache DataSketches Python 5.2.0 exposes
`hll_sketch.deserialize(bytes)` through the upstream wrapper source
`src/hll_wrapper.cpp:100`; its coupon vector is a `std::vector<uint32_t>` via
`std::allocator`, hence glibc `operator new`.

`lab/datasketches2shell-py/` compiles that unmodified upstream wrapper against
the already-pinned verbatim 5.2.0 headers with `nanobind`; only the module
entry point is reduced to `init_hll` because the other upstream sketch
wrappers are irrelevant to this call. Fixed 5.3.0 headers and an ASan build
are separate modules built from the same wrapper. Two new artifacts are
pinned in that directory (`datasketches-python-5.2.0.tar.gz`,
`nanobind-3.1.0-py3-none-any.whl`; hashes in `PROVENANCE.md`). The image is
the library's genuine 16-byte `serialize_compact()` seed with only wire byte 6
and the payload changed. Every probe is a local Python call: no socket, no
external target, no off-loopback traffic.

`bash lab/datasketches2shell-py/run.sh /tmp/ds2-py-w8` gave **`TOTAL PASS=9
FAIL=0` rc 0**, with 5/5 library pins and 2/2 new pins verified:

- benign count 2 and count 8 images: rc 0, estimates
  `2.0000000049670539` and `8.0000001390775086`;
- count 18 (copy of 72 bytes), count 64 (256 bytes) and count 255 (1020
  bytes): the estimate is printed normally, then the process dies in
  interpreter shutdown — rc 134 with `corrupted size vs. prev_size` for
  counts 18 and 64, rc 139 for count 255;
- fixed 5.3.0: benign still returns `2.0000000049670539`, while count 64
  raises `ValueError: Attempt to deserialize invalid CouponList with
  couponCount >= capacity. Found couponCount: 64, capacity: 8` before the
  copy and the process exits 1 cleanly;
- ASan on count 18: `WRITE of size 72` 0 bytes after the 32-byte coupon
  region, with frames `CouponList-internal.hpp:116` ->
  `HllSketchImplFactory.hpp:101` -> `HllSketch-internal.hpp:63` ->
  `hll_wrapper.cpp:100` -> nanobind -> `PyObject_Vectorcall`;
- gdb on count 18: breakpoint at pinned `CouponList-internal.hpp:116`,
  `couponCount=18`, `p=0xbad6f0`. At `p+32`/`p+40` the words go from
  `0x79`/`0x21` (live glibc chunk metadata) to `0x5a5a5a5a5a5a5a5a` after
  the library's own `memcpy`; the backtrace reaches `hll_wrapper.cpp:100`.
  Continuing, the estimate prints and the process aborts with
  `munmap_chunk(): invalid pointer` in `__libc_free(mem=0xbad720)` =
  `p+48`, from `_PyPathConfig_ClearGlobal` during finalisation.

The gdb observation ties the corrupt chunk to the pinned write, and the
5.3.0 control ties the failure to that write rather than to the Python
runtime: the same wrapper and image only fail when the vulnerable 5.2.0
headers perform the copy.

**Disposition: KEEP the real-consumer grade, extend its impact to an
availability failure under glibc, no grade upgrade.** This is an upstream
binding source compiled into a local extension, not an installed wheel or an
application accepting untrusted images over a network, and the input is a
local `bytes` object rather than a socket payload. No chosen pointer value,
leak, natural call-through or execution of attacker-chosen code was seen;
the abort occurs during interpreter teardown, after the estimate returned.
The earlier palloc negative stands. Wake 8 is author evidence only until a
witness replays it from a clean archive including
`lab/datasketches2shell-py/src` and `lab/frontier/datasketches2shell/src`.

**Clean-archive author replay (not a witness verdict).** `git archive df670d1`
of `lab/datasketches2shell-py` and `lab/frontier/datasketches2shell` into
`/tmp/ds2-w8-verify` gave `PY_BUILD_OK library_pins=5 binding_pins=2` and
`run.sh /tmp/ds2-w8-out` `TOTAL PASS=9 FAIL=0` rc 0. Its gdb log froze
`p=0xbad410` with `p+32`/`p+40` going `0x79`/`0x21` to
`0x5a5a5a5a5a5a5a5a`, then aborted in `__libc_free(mem=0xbad440)` = `p+48`.
Only heap bases varied between the working-tree and archive runs. This is an
author replay; the claim stays unwitnessed until an independent mind checks
it.

## Wake 9: stream overload, chosen bytes and compact-flag control (2026-11-21)

Bounded question: wake 1 already showed the stream overload's ASan frame in a
loopback service, but the stream copy had no chosen-byte readback, guard-page
fault or fixed-version control of its own, and no test tying the overflow to
the compact flag that selects `couponCount` as the read length. New standalone
harness `lab/datasketches2shell-stream/stream_driver.cpp` and `run.sh` reuse
the five pinned artifacts in `lab/frontier/datasketches2shell/src`; the
pinned 5.2.0 / 5.3.0 headers are compiled verbatim. The harness image is the
same genuine two-update compact seed with only wire byte 6 and the payload
changed. It feeds the image through a `std::stringstream` and calls the public
`hll_sketch::deserialize(std::istream&)`. The page allocator in readback/guard
modes is a harness stand-in for observation only; no library code is patched.

`bash lab/datasketches2shell-stream/run.sh /tmp/ds2-stream-w9b` gave
**TOTAL PASS=10 FAIL=0 rc 0**, five pins OK, two 5-run readback groups
`sha256=cbf2776389037adaf90d5851a3f55b444b675798b8c8dfdd93809a22f9c25066`.

- **Stream ASan write**: `WRITE of size 256` 0 bytes after the 32-byte coupon
  region, frames `memcpy` <- libstdc++ `basic_streambuf::xsgetn` <- `istream::read`
  <- pinned `common_defs.hpp:82` <- `CouponList-internal.hpp:162` <-
  `HllSketchImplFactory.hpp:86` <- `HllSketch-internal.hpp:57`. Count 255 gives
  `WRITE of size 1020` (988 past). Logs `asan64.log`, `asan255.log`.
- **Chosen bytes through the stream copy**: with the page allocator, count 64
  reads back `+32=5a +48=5a +64=5a +96=5a +128=5a +224=5a +255=5a`; changing
  only the payload to `0xa5` changes every offset. The guard build faults with
  rc 139 at the first past-end store. Log `guard.log`.
- **Causal control**: the same count-64 image with only the COMPACT flag
  (`0x08` at wire byte 5) cleared makes pinned `:161` choose
  `sketch->coupons_.size()` (8) instead of `couponCount`; the run is ASan
  clean and returns `rv=ok`. The overflow therefore follows the declared
  count on the compact stream path, not merely the image length.
- **API and fix controls**: the same image through the byte API still reports
  `CouponList-internal.hpp:116`, confirming two distinct copy sites; pinned
  5.3.0 throws `couponCount >= capacity. Found couponCount: 64, capacity: 8`
  before the stream read with no ASan report; vulnerable count 2 is clean.

**Limits and disposition. KEEP the primitive, no grade change.** This is a
socket-free harness, not a new real consumer or a password/leak path; no
pointer value, natural call-through or attacker-chosen code was observed.
The driver deliberately does not call `get_estimate()` after deserializing a
count-64 image, so a separate past-end *read* through the corrupted
`couponCount_` is neither exercised nor claimed here. No probe left the lab.
This is author evidence only until a witness replays it.

**Clean-archive author replay (not a witness verdict).** `git archive 77a6bc6
lab/datasketches2shell-stream lab/frontier/datasketches2shell` into
`/tmp/ds2-w9-archive` and running that copy's `run.sh /tmp/ds2-w9-archive-out`
gave 10 PASS / 0 FAIL rc 0 with 5/5 pins OK and the same
`sha256=cbf2776389037adaf90d5851a3f55b444b675798b8c8dfdd93809a22f9c25066`
for both five-run groups. No path outside the archive was read. This remains
author evidence until an independent replay.

