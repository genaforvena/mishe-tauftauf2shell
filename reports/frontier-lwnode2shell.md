# frontier brief — lwnode2shell (CVE-2026-135746)

## Ground truth

- Claim: Samsung lwnode has an off-by-one in `String::WriteOneByte()` when
  copying a UTF-16-backed string into a one-byte buffer; a code-unit low byte
  is written one byte past the caller's capacity.
- Sources (read-only): GHSA-mvm7-rjgq-6j36 / CVE-2026-135746, published
  2026-11-24; upstream PR `Samsung/lwnode#188` (merged 2026-11-24T01:37:22Z).
  CVSS 3.1 6.8 `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L`, CWE-787.
- Affected: PR base `b3de7be5` on `main`; fixed by PR #188. No numeric release
  pin is published in the advisory — the fix is a merged commit, and the
  project's `SECURITY.md` says the open-source branch is no longer maintained.
- Scope/ranking: this is a JavaScript runtime bug (in scope as a runtime
  memory-safety find) but **local** (`AV:L`) and a one-byte write. It ranks
  below network-facing candidates; it is staged here because it is the only
  fresh 11/24 advisory with an exact upstream fix and a source-bound trigger
  that fits a short wake. The 11/24 VulnCheck batch was FFmpeg-only (standing
  skip); the other fresh CWE-787 hits were already owned or screened.

## Source-bound mechanism

At pinned `src/api-data.cc:2194-2203`, when the Escargot string lacks 8-bit
content, lwnode converts the UTF-16 buffer to a one-byte `StringRef` and
copies code-unit low bytes:

```c
size_t j = 0;
for (size_t i = start * 2; i < oneByteBufferData.length; i += 2) {
  if (j > static_cast<size_t>(bufferCapacity)) {
    break;
  }
  buffer[j] = ((uint8_t*)(oneByteBufferData.buffer))[i];
  j++;
}
nchars = j;
```

`j > capacity` permits one iteration at `j == capacity`, writing
`buffer[capacity]` out of bounds. PR #188 replaces that with a
`std::min(capacity, length - start)` bound, direct low-byte truncation of the
UTF-16 code units, and a start bound — the fixed control used here.

## Local experiment

`lab/frontier/lwnode2shell/` pins `api-data.cc` at `b3de7be5` and compiles the
**verbatim** loop (hash checked on every run) against stand-in byte arrays:

- Rung 1: deterministic; UTF-16-backed source of 20 code units into an
  8-byte destination.
- Rung 2: `j == 8` passes the `j > 8` guard; the ninth byte is written.
- Rung 3: ASan `heap-buffer-overflow`, `WRITE of size 1`, 0 bytes past the
  8-byte allocation, rc 1.
- Byte control: chosen fill `0x48` and `0x5a` land at `byte8`; upstream fixed
  loop writes 8 bytes, leaves the canary at `0xcc`, and is ASan-clean; safe
  16-byte source is clean in both. `sh run.sh` -> 11 PASS / 0 FAIL.
- Exact pins, hashes and commands: `lab/frontier/lwnode2shell/PROVENANCE.md`.

## Rung-4 feasibility and ceiling

Rung 3 is confirmed on the pinned loop bytes; rung 4 is PARTIAL: a chosen
low byte at a chosen one-past-capacity offset in an extracted harness. No
lwnode or Escargot build, no JS script trigger, no real `Isolate` or V8 API
call, no pointer/IP/command control, no allocator metadata, no rung 5. The
advisory is `AV:L` — there is no network path here — and the stock layout is
UNKNOWN, not a pass.

## Cheapest next experiment

Build pinned lwnode at `b3de7be5` with its Escargot submodule under ASan, run
a UTF-16-encoded script whose string literal has at least `capacity+1`
one-byte-representable code units, call `buffer.write(src, 0, capacity,
'ascii')` on an exactly-sized buffer, and observe the same `WriteOneByte`
frame with the merged PR #188 build and a shorter source as controls. Then
request witness replay before any stronger claim.
