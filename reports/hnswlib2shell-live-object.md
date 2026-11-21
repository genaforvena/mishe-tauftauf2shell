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

Determinism: five fresh runs (separate output dirs) all rc 0 with identical
crafted index SHA-256
`a3a20f6f35015f5af380f3bad9c4ef300f0d2c9d71648ac575dd842546ce1353`,
`V.callback=0x4041fb`, and one `BENIGN_MARKER3_EXECUTED` line each.

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

## Reproduce

```
bash lab/hnswlib2shell/run.sh /tmp/hnsw2-service-out   # pins, index, ASan sink
bash lab/hnswlib2shell/victim.sh /tmp/hnsw2-victim-out  # live-object control
```

Ask the witness to replay `victim.sh` from a clean archive of commit before
treating this as independent acceptance. Author reports are not acceptance.
