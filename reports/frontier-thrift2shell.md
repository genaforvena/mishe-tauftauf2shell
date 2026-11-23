# Frontier brief: Apache Thrift `THeaderTransport::untransform()` — CVE-2026-55971 (thrift2shell)

**STAGED 2026-11-23 W143 — direct-call harness evidence and a live two-pane
target window exist; no operator admission yet.** Provenance and byte-exact
pins: `lab/frontier/thrift2shell/PROVENANCE.md`. Frontier owns no further work
on this target; the operator admits, the witness re-runs.

## 1. Verified ground truth

- Advisory: GHSA-gwj4-q93m-wwqc / CVE-2026-55971, published 2026-07-27,
  Critical, CVSS 9.3
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, CWE-122
  (heap-based buffer overflow) — https://github.com/advisories/GHSA-gwj4-q93m-wwqc
- oss-security post dated 2026-07-24 titles it "C++ ZLIB heap buffer overflow
  (write) in THeaderTransport::untransform()" and says the issue affects Apache
  Thrift before 0.24.0; upgrade to 0.24.0. Fix commit
  `db4a473f3a984eee27273256fe737be5dd175595` ("Read the zlib transform result
  directly in THeaderTransport", Jens Geyer, 2026-06-17) adds a write/read
  round-trip regression test using a 700-byte payload.
- GHSA metadata says "Affected versions: Unknown", "Patched versions: Unknown",
  "No package listed", "Unreviewed"; its own body, the oss-security post and the
  two release blobs agree on `before 0.24.0` / fixed `0.24.0`. The captured
  cve.org page is an 880-byte JavaScript shell with no advisory text, so no
  claim is taken from it. No pinned source claims a shell or RCE.
- Claimed primitive: in the C++ bindings' ZLIB transform path, `untransform()`
  inflates the frame section into the transform buffer, replaces its `sz`
  argument with the *decompressed* length, then copies that many bytes back to
  `ptr`, which still points at the smaller *compressed* receive frame. The
  sender controls the compressed frame bytes and therefore the inflated bytes
  and the overrun length.

## 2. Source-bound mechanism and fix

Byte-exact pins (SHA-256 in `src/SHA256SUMS`): vulnerable `v0.23.0` and the fix
commit's parent, fixed `db4a473f` and released `v0.24.0`, plus
`THeaderTransport.h.v0.23.0`. `git hash-object` of the pinned parent and fix
blobs has prefixes `cdf29cf3d53` / `891059b888e`, the patch's preimage/postimage
indexes. Rendered line numbers are claims; raw bytes rule.

Vulnerable `untransform()`, pinned `THeaderTransport.cpp.v0.23.0:286-301`
(identical copy-back at `THeaderTransport.cpp.parent:320`):

```cpp
    stream.next_out = tBuf_.get();
    stream.avail_out = tBufSize_;
    err = inflate(&stream, Z_FINISH);
    if (err != Z_STREAM_END || stream.avail_out == 0) {
      throw TApplicationException(TApplicationException::MISSING_RESULT,
                                  "Error while zlib deflate");
    }
    sz = stream.total_out;
    ...
    memcpy(ptr, tBuf_.get(), sz);   /* pinned v0.23.0:301 */
```

`ptr` comes from the receive buffer, sized by `ensureReadBuffer()` from the
incoming frame length (pinned `v0.23.0:121`). `tBufSize_` is
`wBufSize_ + DEFAULT_BUFFER_SIZE = 512 + 512 = 1024` (pinned
`THeaderTransport.cpp.v0.23.0:317-324`, header `:71`). The only gate,
`stream.avail_out == 0`, bounds the inflated length by the **transform**
buffer, never by the destination. A highly compressible frame therefore passes
the gate and overruns the receive buffer by `total_out - compressed_len`.

The fix patch replaces the copy with a buffer swap (pinned
`THeaderTransport.cpp.fix:324-326`, released `v0.24.0:328-330`):

```cpp
-      memcpy(ptr, tBuf_.get(), sz);
+      rBuf_.swap(tBuf_);
+      std::swap(rBufSize_, tBufSize_);
+      ptr = rBuf_.get();
```

## 3. Cheapest local experiment

One C++ file, no daemon, socket, Thrift process, protocol exchange or network.
Include the **complete** verbatim `untransform()` from four pinned blobs
(v0.23.0, fix parent, fix commit, v0.24.0) in a driver with stubbed
`TApplicationException`, buffer and `resizeTransformBuffer()`/`setReadBuffer()`
environment. Compress 700 identical `0x42` bytes (the fix patch's own test
payload) to 31 bytes; give the function a 31-byte heap destination (the
compressed-frame size), a 1024-byte transform buffer and an adjacent 4096-byte
`0xCC` sink. Chosen marker bytes `41/5a/7a/3c/7b/42/7b` sit at inflated offsets
0/16/32/64/128/256/699. Fixed and v0.24.0 are fixed controls; the fix parent is
a second vulnerable control; 4 bytes is the safe control; 4096 bytes exercises
the existing gate before any copy.

## 4. Rung-4 feasibility and risks

Favourable: one unbounded `memcpy` with caller-influenced length and fully
controlled source bytes; the real caller/transform bounds are visible in pinned
source; the fix differs by one statement. Constraints measured here: the
destination is a 31-byte harness allocation (not a real THeader frame pool);
ASan faults on the WRITE before chosen bytes can be read downstream, so the
smear is observed in plain builds against an adjacent harness sink; the sink's
0xCC bytes are overwritten with the chosen markers, which are byte patterns,
not pointers, gadgets or a command. The real allocation neighbours of a live
THeader receive buffer are UNKNOWN.

## 5. Observations

- Harness `PASS=71 FAIL=0` three times plus a clean-`/tmp` replay; normalized
  trace `c12ba2145cec292e618d2f50677887c61a56d577b012577cd50c304731bbe556`.
- Rung 1: `COMPRESSED_LEN=31 DECOMPRESSED_LEN=700 DEST_BYTES=31
  OVERFLOW_BYTES=669 TBUF_SIZE=1024` from pinned arithmetic, no call needed.
- Rung 2: vulnerable v0.23.0 and the fix parent return `SET_SIZE=700`,
  `SETPTR_IS_RBUF=1`, `DST_UNCHANGED=0`, and smear the adjacent object
  (`SINK_DIST=48`, `SINK_BYTE_1=42`, `SINK_BYTE_16=3c`). Fix commit and v0.24.0
  return `SETPTR_IS_ORIG_TBUF=1`, leave `DST_UNCHANGED=1` and the sink at 0xCC;
  4096 bytes is rejected by the existing gate in every variant.
- Rung 3: gcc and clang ASan `heap-buffer-overflow`, `WRITE of size 700` at
  pinned `THeaderTransport.cpp.v0.23.0:301` in `untransform`, 0 bytes after the
  31-byte region; fix parent faults at `:320`; fix, v0.24.0 and safe inputs
  are clean.
- Rung 4: chosen bytes observed at inflated offsets 0/16/32/64/128/256/699
  (`41/5a/7a/3c/7b/42/7b`); gdb at pinned line `:301` shows `sz=700` and the
  markers in the frame, versus the fixed build hitting the swap with `sz=31`
  and an intact sink.

## 6. Ceiling / handoff

Direct call with stubbed object environment; no real `thrift` process,
`THeaderTransport` header/framing parser, transport stack, socket, server,
peer, wire exchange, network, ASLR/grooming study, pointer control, ROP chain,
command, marker side effect or witness verdict. Whether a live C++ server
actually reaches this path with attacker-supplied frames remains UNKNOWN; the
advisory's AV:N vector is a claim, not a lab observation. A dedicated target
mind should first build a vulnerable Thrift C++ server with ASan, enable the
ZLIB transform, and observe the sink on living bytes from a loopback client,
then determine what the real receive-buffer allocation places after the frame
before considering any benign marker. Do not relabel placed heap bytes as
remote execution.
