# ipfixcol2shell — live loopback TCP replay (2026-11-21)

## What this is

The witness verdict on the admitted handoff was ESTABLISHED AS CLAIMED
(tape #712): the frontier pipe harness is accepted, and live collector /
allocator remained UNKNOWN. This lab directory takes the next bounded step:
it compiles the TCP input plugin's **real** `Lz4Decoder.cpp`,
`DecodeBuffer.cpp`, `ByteVector.cpp` and `read_until_n.hpp` verbatim from
pinned upstream tag sources, accepts a connection on a real 127.0.0.1:0 TCP
socket, sends the same start/message headers, and runs the decode under the
host's real `liblz4.so.1` and stock glibc (and under ASan).

It is **not** a full `ipfixcol2` daemon build. That path is blocked on this
host by missing `libfds` (not in apt), missing `lz4.h`/`liblz4-dev` and missing
`rst2man`; do not describe it as a daemon observation. What is real here: the
decoder / consumer code, the socket, the wire bytes, the allocator and the
liblz4 library. What is harness-owned: `driver.cpp`, two ABI shims in
`shims/`, and `gen_wire.py`. No probe ever leaves loopback; source fetching by
`stage.sh` is provisioning only.

## Reproduce

```
cd lab/ipfixcol2shell-live && sh stage.sh && sh run.sh
```
`stage.sh` fetches and sha256-verifies the v2.8.0 and v2.9.0 source tarballs
(`460f1272…` and `fa98b31c…`), extracts them into `v280/` / `v290/`, and
checks that `Lz4Decoder.cpp` still equals the frontier pins
(`3e618628…` vulnerable, `46a0fc8b…` fixed). `run.sh` then builds four
variants (vulnerable/fixed × ASan/plain), runs attack, differential, crafted
and benign wires, and writes `out/trace.txt` plus `out/trace.sha256`.

Observed 2026-11-21: **9 PASS / 0 FAIL**, three consecutive runs byte-identical,
trace
`sha256=b81b947cf21f4ab92c6f268534dfbe8fbd6c3eb7da35ee5e9caab000e5471600`.

## Clean archive replay (2026-11-21 ~09:12Z)

Two `git archive HEAD` (`74b83ab`) extractions of `lab/ipfixcol2shell-live/`
into `/tmp/ipx-live-a` and `/tmp/ipx-live-b` (different absolute paths), plus
the working tree: `sh run.sh` returned 0 with 9 PASS / 0 FAIL in all three,
each fetching its own pinned tarballs, and the raw traces were byte-identical
(`cmp` clean A↔B and A↔working tree), trace
`sha256=b81b947cf21f4ab92c6f268534dfbe8fbd6c3eb7da35ee5e9caab000e5471600`.

## Observed facts

- Bind is `127.0.0.1:<ephemeral>` in every case; no other address is used.
- ASan, vulnerable, `buffer_size=24`, `decompressed_size=65000`, all-literals
  payload: `ERROR: AddressSanitizer: heap-buffer-overflow`, `WRITE of size
  65000`, `0 bytes after 24-byte region`, allocation at `Lz4Decoder.cpp:184`
  via `read_start_header` `:131`, write call at `decompress` `:145`. These are
  the real upstream filenames and line numbers, not the frontier `#line`
  staging. Rung 3 therefore holds on the loopback path too.
- ASan and plain fixed builds reject the same bytes with
  `LZ4 Decoder: invalid decompressed size`; no ASan report.
- Benign wire (one whole 24-byte IPFIX message inside a 24-byte ring) decodes
  cleanly in both builds: `messages=1 decoded_bytes=24`.
- Stock glibc, no sanitizer, no replaced allocator, `0x5a` payload: SIGSEGV in
  `unlink_chunk` from `_int_malloc` → `_int_realloc` →
  `ByteVector::reserve` (`DecodeBuffer.cpp:94`) → `Lz4Decoder::decompress`
  (`:163`). GDB at the fault: `rax = 0x5a5a5a5a5a5a5a58`, i.e. the
  attacker's chosen bytes occupy the corrupted chunk's 8-byte size field and
  are masked by glibc before the check. The `0x41` differential gives
  `rax = 0x4141414141414140` at the same frame. Benign input does not crash.
- Crafted payload: with a valid `0x6000` size at ring offset 24 and the same
  value at `p + size`, chosen bytes `0x4141414141414141` / `0x4242424242424242`
  are placed in `p->fd` / `p->bk`. The stock build faults at
  `unlink_chunk+39` (`cmp 0x18(%rax),%rdi`) with
  `rax = 0x4141414141414141`: chosen wire bytes are consumed as a heap
  pointer by glibc's allocator. This is **chosen pointer bytes**, not a chosen
  valid address, write-what-where, vtable/return-address overwrite or marker
  execution. The sentinel is noncanonical and the process dies on the
  dereference.

## Rung assessment

- Rung 1–3: confirmed on verbatim pinned sources over a real loopback TCP
  socket, with fixed and benign controls.
- Rung 4: still **INSTRUMENTED**, but now with a stock-allocator observation
  beyond the frontier mmap collaborator: chosen bytes reach glibc chunk
  metadata, and a crafted payload places chosen bytes in a pointer that
  `unlink_chunk` dereferences. Conditions: this host's glibc 2.39 layout and
  allocation order, a payload that sculpts the size/prev_size fields, and a
  noncanonical sentinel. No valid target address, control-flow diversion or
  execution was observed. The advisory itself scores availability only.
- Full-daemon frames, shipping allocator, post-write pointer retargeting and
  code execution remain UNKNOWN, not passes.

## Preserved negative results

- A first plain build with a passive 24-byte-allocation logger faulted while
  reading back offset 64999 from unrelated small allocations; that run is not
  evidence about overflow placement. The plain build used for the observations
  above has no allocation override.
- Early benign payloads (8 bytes of `0x5a`, then a 24-byte message with too
  few body bytes) threw `Received incomplete message.` from the real
  `DecodeBuffer`; they were replaced by a complete 24-byte IPFIX message, not
  silently relabeled as a pass.
- A crafted chunk size of `0x41` hit glibc's `_int_malloc` assertion
  `size >= nb`; `0x6001` hit `corrupted size vs. prev_size` until the
  prev_size write was moved to `p + size` (payload offset 24592), matching the
  host's `unlink_chunk` comparison. Those failures are why the final crafted
  layout uses `0x6000`.
- The full collector build was not attempted past the dependency screen:
  `libfds`, `lz4.h` and `rst2man` are absent on this host.
