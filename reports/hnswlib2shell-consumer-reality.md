# hnswlib2shell — consumer-reality experiment (2026-11-21)

CVE-2026-124959 (CNA CERT/CC, CWE-787, no CVSS in the CVE record).
Affected hnswlib 0.5.0–0.9.0. **The fixed side is the UNMERGED PR #677 head
`280cb597…`, not a released version**; no released-fix claim is made anywhere
in this report. This is a lab-only, loopback-only synthetic consumer: no third
party index-loading application was run, and no network reachability or
authentication is claimed.

## What was added

`lab/hnswlib2shell/service.cpp` accepts one index file from a TCP socket bound
to `127.0.0.1`, writes the received bytes to a file and calls the ordinary
pinned v0.9.0 constructor `HierarchicalNSW<float>(&space, path)`. The library
headers come verbatim from the pinned `v0.9.0.tar.gz`; no library source was
patched. `client.py` sends one file. `run.sh` checks the seven frontier pins,
builds the service under ASan and unsanitized, generates the hostile indexes
with frontier's own serializer driver and serves them. `chosen.sh` freezes the
unsanitized service under gdb and checks a file-chosen value in real heap
metadata. All probes stay on loopback ports opened by this harness.

## Established observations

1. **End-to-end service path.** The client sent 71160 bytes to the service;
   the received file SHA-256 was
   `e192bcdc1477decfdefc0c422d0911bc598efa21d7caf98edbf4abe126bfd46f`,
   byte-identical to the crafted index. Header read by the service:
   `stored_capacity=2 count=512 per=128`.
2. **ASan in the service process.** `run.sh` exits 0 with
   `service_asan_write_at_pinned_sink=1`. The service reports
   `heap-buffer-overflow`, `WRITE of size 65472`, `0 bytes after 256-byte
   region`, allocated at pinned `hnswalg.h:776`, written at `hnswalg.h:779`,
   reached from `hnswalg.h:85` and `service.cpp:67`. The consumer chain is
   `std::istream::read` → `std::basic_filebuf::xsgetn` → intercepted `read`;
   this is the actual consumer on this host, not an assumed memcpy shape.
   The capacity-fits control through the same socket loads clean.
3. **Real unsanitized heap metadata, no interposer.** gdb at `hnswalg.h:779`
   froze the service with `data_level0_memory_=0x…34f0`, a 272-byte glibc chunk
   (`size=0x111`). The adjacent top chunk's size field at `dst+264` read
   `0x000000000000ba11` before the copy. A conditional `malloc` breakpoint
   after the copy showed that field overwritten with attacker file bytes:
   for the uniform `0x5a` index it became `0x5a5a5a5a5a5a5a5a` and the process
   aborted with `malloc(): corrupted top size`; with the 8 bytes at file offset
   `96+264=360` set to `88 77 66 55 44 33 22 11`, the field became exactly
   `0x1122334455667788` (`chosen.sh`: `chosen_value_present=True`, rc 0).
   The bytes were carried by the library's own `std::istream::read`; no malloc
   interposer was used in this build.

## Grade and limits

Rungs 1/2/3 remain ESTABLISHED (frontier W73 verdict: ESTABLISHED AS CLAIMED).
Rung 4 is now **INSTRUMENTED plus real-heap-metadata chosen bytes in a
synthetic loopback service**: chosen file bytes at a chosen offset reach the
real glibc allocator's top-chunk size field through the ordinary load path,
without a placement shim. This is not control-flow or object-header control:
the first real neighbour on this host is the top chunk, not a live object;
glibc validates that field at the next malloc and aborts. No pointer, vtable,
return address, guarded-page write, benign marker execution or third-party
consumer was observed — all UNKNOWN. The uniform-marker case demonstrates
deterministic denial of service in the synthetic service, not shell execution.

## Negative results and instrument caveats (preserved)

- First service revision read four header fields into a three-element array;
  ASan correctly reported a stack-buffer-overflow in `service.cpp:61`, before
  any library load. Fixed to four elements; the pinned-sink result above is
  from the corrected build.
- A gdb hardware watchpoint on `*(unsigned long*)(dst+264)` did **not** stop on
  the library's wide store; the process reached the glibc abort first. This is
  a watchpoint blind spot, not evidence that the write missed. The conditional
  `malloc` breakpoint supplied the observation.
- `next` at `hnswalg.h:779` in gdb ran past the intended line into the
  downstream abort, so it could not freeze the post-copy frame.
- One attempted port (`49374`) was already bound; the run was repeated on a
  free loopback port.
- The exception/malloc frames at the freeze (`xsgetn` → `__throw_ios_failure`
  → `__cxa_allocate_exception` → `malloc`) are downstream consequences of the
  corrupted allocator state, not the write primitive itself.

## Reproduce

```
bash lab/hnswlib2shell/run.sh /tmp/hnsw2-service-out
bash lab/hnswlib2shell/chosen.sh /tmp/hnsw2-service-out
```

Logs and crafted indexes are under the chosen output directory (untracked lab
artifacts). The fixed-side guard was verified by frontier, not re-measured
here: it throws `Index seems to be corrupted or unsupported` at the UNMERGED
PR #677 head, with no ASan report. Ask the witness to replay these two commands
before treating them as independent acceptance.
