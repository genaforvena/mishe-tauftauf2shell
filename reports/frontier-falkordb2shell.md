# Frontier brief — FalkorDB Bolt/WebSocket extended-length heap over-write (Falkordb2Shell)

**Status: new unowned candidate promoted to a live find. Rungs 1/2/3 PASS on a
standalone file-only C harness that extracts the exact vulnerable functions;
rung 4 NOT demonstrated.** The write primitive is an XOR with the attacker's
repeating 4-byte WebSocket mask, so the written value is `K:K` over 8 bytes,
not an arbitrary pointer. No charter or target mind named `falkordb2shell`
existed when checked (charter list and chat tape read 2026-11-20 17:40Z).

## Verified ground truth (claim sources + this lab, 2026-11-20)

- **Advisory**: CVE-2026-107909 / GHSA-x67x-q5pm-p9h7, "A heap-based
  out-of-bounds write in the ws_read_frame function (src/bolt/ws.c) and the
  buffer_apply_mask function (src/bolt/buffer.c)" (NVD-sourced, published to
  GitHub Advisories 2026-10-09). CWE-787. CVSS 4.0 8.8,
  `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H`.
- **Claimed primitive**: a remote unauthenticated peer sends a WebSocket frame
  with a 64-bit extended payload length to the Bolt port; the length is not
  bounded and the only bounds check in `buffer_apply_mask()` is an `ASSERT()`
  compiled out of release builds, so the code XORs memory beyond the receive
  buffer with the attacker's masking key. The advisory claims DoS and possible
  heap corruption. Deployment condition: Bolt endpoint enabled (`BOLT_PORT`),
  disabled by default.
- **Affected / fixed (claims)**: FalkorDB before 4.20.0. Upstream fix
  `0b11a00b34b25c4d4fdfe55f0a35c8a00593bd7d` (2026-07-08, "remove bolt
  support", PR #2170) **deletes the entire Bolt/WebSocket subsystem**; parent
  is `40780e992ecc11f598ce3f4f65e04367f9abae2f`. There is no patched
  `ws_read_frame()` to diff — the fixed configuration has no such code. The
  `FIXED` build in this lab is a locally added length guard, not an upstream
  patch; it is labelled as such everywhere.
- **Claim sources read (external claims, not lab findings)**: CVE record and
  GitHub advisory pages; upstream fix commit and full patch; PR #2170; raw
  source `src/bolt/{ws.c,buffer.c,buffer.h,RG.h,bolt_api.c}` at the vulnerable
  parent. No exploit page, no external probe.

## Source-bound mechanism (read from the vulnerable parent, not inferred)

`BoltRequestHandler()` (`src/bolt/bolt_api.c:686-687`) calls
`ws_read_frame(&current_read)` whenever the client negotiated WebSocket.
`ws_read_frame()` (`src/bolt/ws.c`) reads the 2-byte frame header, and for
length code `127` reads **eight attacker bytes** into `uint64_t payload_len`;
if the MASK bit is set it reads four more bytes as `uint32_t masking_key` and
calls:

```c
buffer_apply_mask(*buf, masking_key, payload_len);
```

`buffer_apply_mask()` (`src/bolt/buffer.c:391-408`) starts with
`ASSERT(buffer_index_length(&buf) >= payload_len)` and calls
`buffer_index_advance(&end, payload_len)`. `src/RG.h` defines
`#define ASSERT(X)` when `RG_DEBUG` is off (it is commented out), so both
checks vanish in release. `buffer_index_advance()` takes a `uint32_t n`, so
the 64-bit length is truncated; the resulting `end.chunk` drives a loop that
calls `buffer_apply_mask_single()` on every chunk index up to `end.chunk`,
whether or not that chunk exists.

`buffer_apply_mask_single()` (`src/bolt/buffer.c:369-388`) computes
`payload = chunks[chunk] + offset`, builds `double_mask[4]` from the single
4-byte key, then XORs 8-byte words with `offset_mask` across
`BUFFER_CHUNK_SIZE - offset` bytes of each chunk (4096, from `buffer.h`).
Consequences kept separate:

1. **Length control is unconditional**: with zero payload bytes received, a
   declared length of 4144 makes the loop mask 4082 bytes in chunk 0 and 62
   bytes in chunk 1 — all beyond the 14 received header bytes.
2. **Byte control is `K:K`**: every 8-byte word is XORed with the same
   4-byte key repeated. A zeroed field becomes `0x4242424242424242` for
   `K=0x42424242`, or `0x4141414141414141` for `K=0x41414141`. An arbitrary
   8-byte pointer cannot be written unless the original 8 bytes are already
   known/groomed to satisfy `(target ^ original) = K:K`.

## Lab result — deterministic differential, chosen mask, ASan report

Harness `lab/frontier/falkordb2shell/{ws_overflow.c,run.sh}`; full
reproduction in Reproduce. Pinned digests from `logs/digests.txt`:
`ws_overflow.c` `c0c8179cb198ec14b6bde7fcd9f0ccc5df7e3ccdb033c683f094a3dc79ac072c`,
`run.sh` `a4d4d8f52a9345ec7b84e0e564591083961b01a61d657adf4984c13da6b9e884`.
`bash run.sh` rebuilds all three variants and prints `ALL CHECKS PASS`.

Observed (all inputs local buffers; no listener, no socket):

```
frame payload_len=4144 mask=0x42424242 writes=525 oob_writes=525
canary offset=104 before=0x0000000000000000 after=0x4242424242424242
frame payload_len=4144 mask=0x41414141 writes=525 oob_writes=525
canary offset=104 before=0x0000000000000000 after=0x4141414141414141
control: payload_len=8, 8 bytes supplied -> oob_writes=0, canary unchanged
fixed:   FIXED: reject payload_len=4144 available=0 -> writes=0, oob_writes=0
ASan:    ERROR: AddressSanitizer: heap-buffer-overflow, READ of size 8,
         in buffer_apply_mask_single (ws_overflow.c:138), rc 1
repeat:  3/3 vulnerable runs with oob_writes=525
```

Rungs 1/2/3 use full 4096-byte chunks; the detector there is the source-level
write counter plus the canary, because the mask writes stay inside the chunk
allocation. The ASan run uses a **lab layout** with 64-byte second/third
chunks so the same 4096-byte-per-chunk write crosses a redzone and ASan names
the exact source line. Upstream allocates 4096 bytes per chunk, so a stock
process would not get that ASan report — the report proves the write extent,
not a production-sized allocation. Logs: `lab/frontier/falkordb2shell/logs/`.

Two measurement caveats from the witness replay: ASan flags the 8-byte *load*
(the read half of `^=`), not a store, at `ws_overflow.c:138`; and `525` counts
write operations (word XORs plus trailing bytes), not bytes — the 4144-byte
out-of-bounds extent is correct. The harness allocates `chunks[1]`, so it does
not model an additional out-of-bounds read of the `chunks[]` array when
`end.chunk` exceeds the allocated chunk count; whether that read occurs in a
stock build stays UNKNOWN.

## Rung ladder — honest grading

- **Rung 1 (reproducible trigger): PASS.** A 14-byte masked frame header with
  no payload and `payload_len=4144` deterministically drives 525 masked writes
  past the received bytes; the in-bounds control (length 8, 8 bytes supplied)
  produces zero OOB writes.
- **Rung 2 (observed state failure): PASS.** A zero canary at chunk offset 104
  becomes the chosen `K:K` value; switching the mask to `0x41414141` changes
  the written value byte-for-byte, so the bytes are attacker-chosen.
- **Rung 3 (confirmed memory corruption): PASS.** ASan reports a
  heap-buffer-overflow (READ of size 8 at the `^=` load) at the XOR site with
  the short-chunk lab layout; the source-level counter independently observes
  all 525 OOB write operations with the faithful 4096-byte layout.
- **Rung 4 (demonstrated security impact): NOT DEMONSTRATED.** The primitive
  writes a repeating 4-byte key, not a chosen 8-byte value or address. No
  pointer hijack, no chosen address, no benign marker execution. A live
  FalkorDB process with `BOLT_PORT` enabled, the handshake path, real heap
  layout and the first out-of-bounds `chunks[]` pointer remain UNKNOWN — this
  lab exercised the extracted C functions only; the single allocated chunk
  also leaves an OOB `chunks[]` array read unmodelled.

## Feasibility and cheapest next step

Tractability **HIGH for rungs 1–3** (done), **OPEN for rung 4**: small C
subsystem, exact vulnerable parent commit, public removal commit, no hardware
gate. The structural blocker is the `K:K` write pattern: a target field with
known original bytes is needed for arbitrary 8-byte control. The natural lane
is to measure what allocator metadata adjacent to a real 4096-byte chunk
contains (glibc chunk header, `chunks[]` array entries) and test whether a
chosen mask can turn an adjacent size/length field into a chosen repeated
pattern that produces a controlled second write. Preserve the in-bounds
control and every negative result. A loopback-only FalkorDB build with
`BOLT_PORT` enabled would move the network claim from UNKNOWN to evidence.

## Reproduce

```
cd lab/frontier/falkordb2shell
bash run.sh      # builds vuln/fixed/asan, runs trigger + controls + ASan,
                 # writes logs/ and logs/digests.txt, prints ALL CHECKS PASS
```

All inputs are local files and buffers. Only read-only provisioning fetched
advisories and upstream source. No listener, no socket, no external target.

## What would change this assessment

- A fixed release that still contains a patched `ws_read_frame()` would change
  the version boundary; the observed fix removes the subsystem instead.
- A chosen mask turning a real 8-byte pointer or allocator size field into a
  chosen value (not just `K:K`) would promote rung 4.
- A live loopback `BOLT_PORT` service that rejects the frame before
  `ws_read_frame()` would reduce the network claim to UNKNOWN while leaving
  the extracted-function result intact.
