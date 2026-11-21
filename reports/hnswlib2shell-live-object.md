# hnswlib2shell — live-object pointer control (2026-11-21)

CVE-2026-124959 (CNA CERT/CC, CWE-787, no CVSS in the CVE record).
Affected hnswlib 0.5.0–0.9.0. **The fixed side is the UNMERGED PR #677 head
`280cb597…`, not a released version**; no released-fix claim is made here.
This is a lab-only, loopback-only synthetic consumer. No third-party
index-loading application, network reachability or authentication is claimed.

## Question and result

The earlier consumer-reality run (`reports/hnswlib2shell-consumer-reality.md`)
put file-chosen bytes in the real glibc **top-chunk** size field — allocator
metadata, not a live object. This run closes that specific gap: with ordinary
glibc `tcache` grooming performed by the *consumer before load*, the library's
own `malloc(256)` at pinned `hnswalg.h:776` reuses a freed `0x110` chunk and a
**live object with a function-pointer field sits immediately after it**. The
library's own `input.read` at `:779` then writes file-chosen bytes over that
live object's fields, including its function pointer. A call through that
overwritten pointer reaches a benign marker inside the service process.

## Method

`lab/hnswlib2shell/victim.cpp` is the existing loopback service plus a
deterministic layout step; the pinned v0.9.0 headers are compiled verbatim and
**no library source is patched and no malloc interposer is used**:

```
void *G = malloc(256);
CacheEntry *V = new CacheEntry();   // {magic, callback, refcount, label[32]}
V->callback = &benign_marker2;      // original, benign
free(G);                            // tcache[0x110] = G; V is next physical chunk
hnswlib::HierarchicalNSW<float> idx(&space, path);   // ordinary load constructor
```

`hnswalg.h` writes `cur_element_count * size_data_per_element_` = 512×128 =
65536 bytes from `data_level0_memory_`, whose level0 image begins at file offset
96. Glibc places V's chunk header at `dst+256`/`dst+264` and V's user fields at
`dst+272`. `victim.sh` learns V's real chunk size and the top-chunk size from
the service's own pre-write printf, then crafts the index so V's and the top
chunk's headers stay valid and only V's live fields change:

| file offset | dst offset | field | before | chosen |
|---|---|---|---|---|
| 360 | +264 | V chunk size | `0x41` | `0x41` (preserved) |
| 368 | +272 | `V.magic` | `0x43414348454e5452` | `0x1111111111111111` |
| 376 | +280 | `V.callback` | `0x4041be` (`benign_marker2`) | `0x4041fb` (`benign_marker3`) |
| 384 | +288 | `V.refcount` | `0x1` | `0x3333333333333333` |
| 392 | +296 | `V.label[32]` | `C`×32 | `D`×32 |
| 424 | +328 | top chunk size | `0xd9e1` | `0xd9e1` (preserved) |

The service is built `-no-pie -O0 -g` so the benign marker addresses are
stable. The crafted callback is a *different* function from the original,
so a call through the field is a real diversion, not a no-op rewrite.

## Observed

`bash lab/hnswlib2shell/victim.sh /tmp/hnsw2-victim-out` — rc 0, `VICTIM
POINTER CONTROL OBSERVED rc 0` and `CAPACITY_FITS_CONTROL_CLEAN rc 0`. The
client sent 71160 bytes; the seven frontier SHA-256 pins checked (pins.log).

- gdb froze at the pre-write breakpoint `hnswalg.h:779` with
  `G=0x43d4e0 V=0x43d5f0 delta=272` (one 0x110 chunk), `callback_before=0x4041be`.
- After the library's own `std::istream::read`, at the downstream allocator
  abort: `V_size_field=0x41` (V still a valid live chunk),
  `V.magic=0x1111111111111111`, `V.callback=0x4041fb`,
  `V.refcount=0x3333333333333333` — every chosen field present at its chosen
  offset.
- Calling through the overwritten pointer from the gdb stop printed
  `BENIGN_MARKER3_EXECUTED` inside the service process.
- Capacity-fits control (same socket, same grooming): `victim_load=loaded`,
  `AFTER_LOAD magic=0x43414348454e5452 callback=0x4041be refcount=0x1` —
  the live object is unchanged; attribution is to the corrupt capacity/count,
  not to the grooming.

Determinism: five author runs (separate output dirs) all rc 0 with identical
crafted index SHA-256
`a3a20f6f35015f5af380f3bad9c4ef300f0d2c9d71648ac575dd842546ce1353`,
`V.callback=0x4041fb`, and one `BENIGN_MARKER3_EXECUTED` line each. **This
digest is build-layout-specific, not a portable pin** (W74 nit below): the
crafted index embeds the learned top-chunk size, which varies with the build.

## Grade and conditions

Rung 4 **DEMONSTRATED in the lab build with stated conditions**: chosen bytes
at chosen offsets in a live object, control of a pointer-typed field, and
benign marker execution reached through that field. Conditions: synthetic
loopback consumer; consumer-side `tcache` grooming to place a live object
after the loader's buffer; non-PIE build with fixed marker addresses; the call
through the overwritten pointer was invoked from gdb at the post-read stop,
**not** by a natural consumer code path; the loader then aborts downstream on
allocator state. No third-party consumer, natural call-through, return-address
or vtable target on a production stack, or shell execution was observed — all
UNKNOWN. The ASan `WRITE of size 65472` at `hnswalg.h:779` remains the
sanitizer-grade sink from the earlier report; this run is unsanitized.

## Negative results and instrument caveats (preserved)

- An earlier attempt set the crafted callback to the marker address that was
  already in `V.callback`; the post-read value was unchanged and no diversion
  could be claimed. Fixed by choosing the distinct `benign_marker3` address.
- Preserving the top-chunk size field at file offset 424 did not prevent the
  downstream `malloc(): corrupted top size` abort, so a clean freeze at
  `hnswalg.h:781` was not obtainable; the post-read observation was taken at
  the resulting SIGABRT stop instead. The observed fields at offsets up to
  `+328` were already stored at that point; whether the full 65536-byte read
  completed before the abort is UNKNOWN on this host.
- A conditional `malloc` breakpoint keyed on a *changed* callback value was
  tried first; it did not stop before the abort in the no-diversion revision.
  The SIGABRT stop is the reliable observation point on this host.

## Witness verdict (W74, 2026-11-21)

Witness W74 independently replayed both hnswlib2shell claims and reported both
ESTABLISHED AS CLAIMED at the labeled grade (chat tape #948):

- Consumer-reality (commit `6445c8a`, tape #935): clean git archive with the
  frontier pin dir; `run.sh` gave the ASan `WRITE of size 65472` at pinned
  `hnswalg.h:779` into the `:776` 256-byte region inside the service, received
  bytes SHA `e192bcdc...` matched, capacity-fits control clean, seven pins OK.
  `chosen.sh` showed the real top-chunk size field `0xba11` →
  `0x1122334455667788` from file bytes at offset 360, gdb rc 0.
- Live-object pointer control (commit `2a271d3`, replayed though not routed):
  tcache `G=0x…d4e0 V=0x…d5f0 delta=272`; after the library's own read
  `V.size` stayed `0x41`, `V.magic=0x1111111111111111`,
  `V.callback=0x4041fb` (distinct marker3; original marker2 `0x4041be`),
  `V.refcount=0x3333333333333333`, all byte-exact; `BENIGN_MARKER3_EXECUTED`
  via the overwritten pointer; capacity-fits control clean. The witness
  accepted the stated conditions: the call was invoked from gdb at the
  post-read stop, not a natural consumer path; non-PIE build; consumer-side
  tcache grooming; unmerged PR head is the fixed side; downstream allocator
  abort; full 65536-byte read completion stays UNKNOWN. No replay is owed.

NON-MATERIAL NIT from W74: the determinism digest above is
build-layout-specific, not a portable pin. The witness's clean-archive build
produced `2f17ee97...` (stable across three fresh output dirs), because the
crafted index embeds the learned top-chunk size (`0xd9f1` in that build versus
`0xd9e1` here). The mechanism and grade are unchanged; the digest is an
environment-specific observation, not a portable fixture.

## Witness verdict (W75 supplemental, 2026-11-21)

Witness W75 discharged the two counterexamples it had raised in tape #942
against the live-object claim (chat tape #952), replaying a clean archive of
commit `2a271d3`: seven pins OK, `VICTIM POINTER CONTROL OBSERVED` plus
`CAPACITY_FITS_CONTROL_CLEAN`, both rc 0, `G=0x…d4e0 V=0x…d5f0 delta=272`, V
chunk `0x41` before and after, `callback=0x4041be → 0x4041fb`, chosen
`magic`/`refcount` byte-exact, and `BENIGN_MARKER3_EXECUTED` via the gdb-invoked
call.

1. Image-carried pointer, not a grooming consequence. The witness copied the
   crafted index and changed only the eight callback bytes at file offset 376
   from `0x4041fb` back to the original marker2 address `0x4041be`. The same
   freeze script then read `V.callback=0x4041be`, called through it and printed
   `BENIGN_MARKER` (marker2), with chosen `magic`/`refcount` unchanged. The
   diverted pointer comes from the file bytes, not from the groomed layout.
2. Victim live at the store. `victim.cpp:91-97` does `G=malloc(256)`,
   `V=new CacheEntry` with initialized `magic`/`callback`/`refcount`, then
   `free(G)` into `tcache[0x110]`; the library's own `malloc(256)` at
   `hnswalg.h:776` reuses G. gdb showed V's `0x41` chunk and constructor fields
   before the read and the chosen fields after, with no re-store before the
   gdb-invoked call.

Grade unchanged: ESTABLISHED AS CLAIMED at the disclosed lab conditions
(gdb-invoked call, non-PIE, consumer grooming, unmerged PR head fixed side).
The NIT was re-observed: the witness's clean build again gave index digest
`2f17ee97...`, not this report's `a3a20f6f...`; its probe top size `0xd9f1`
versus the actual run `0xd9e1`. No replay is owed.

## Reproduce

```
bash lab/hnswlib2shell/run.sh /tmp/hnsw2-service-out   # pins, index, ASan sink
bash lab/hnswlib2shell/victim.sh /tmp/hnsw2-victim-out  # live-object control
```

Author reports are not independent acceptance; the W74 and W75 replays above
are the independent verdicts.
