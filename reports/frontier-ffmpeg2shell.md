# Frontier brief: FFmpeg `librist_read()` — CVE-2026-75143 (ffmpeg2shell)

**STAGED 2026-11-23 W142 — direct-call harness evidence and a live two-pane
target window exist; no operator admission yet.** Provenance and byte-exact
pins: `lab/frontier/ffmpeg2shell/PROVENANCE.md`. Frontier owns no further work
on this target; the operator admits, the witness re-runs.

## 1. Verified ground truth

- Advisory: GHSA-7qc3-xqxj-426p / CVE-2026-75143, published 2026-08-19,
  Critical, CVSS 9.3
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, CWE-122
  (heap-based buffer overflow) —
  https://github.com/advisories/GHSA-7qc3-xqxj-426p
- Fix commit `1c10bcc2e17255dacb717a25ab3db142ce390602` ("avformat/librist:
  honor the caller buffer size in librist_read", parent `7b05d16c`), PR
  https://code.ffmpeg.org/FFmpeg/FFmpeg/pulls/24089. The advisory's
  affected/patched fields say "Unknown"; release-tag bytes were checked
  directly (section 2).
- Claimed primitive: `librist_read()` overwrites its `size` argument with the
  received RIST payload length and copies that many bytes into the
  caller-provided destination. Via `async:rist://`, the async wrapper calls
  the inner reader with a buffer of `FFMIN(4096, fifo_space)` bytes
  (`libavformat/async.c:235` → `:140`), while the RIST payload can be up to
  `MAX_PAYLOAD_SIZE = 9972` bytes. A remote RIST sender controls the payload
  length and bytes; up to 5876 bytes land past the caller's buffer.

## 2. Source-bound mechanism and fix

Byte-exact pins (SHA-256 in `src/SHA256SUMS`): `librist.c.7b05d16c` and
`librist.c.n9.0` are identical (`bf749fb2…a7c`); `librist.c.1c10bcc2` and
`librist.c.n9.0.1` are identical (`531f4332…d1e`). Rendered line numbers are
claims; raw bytes rule.

Vulnerable `librist_read()`, pinned `librist.c.7b05d16c:200-234`:

```c
    if (data_block->payload_len > MAX_PAYLOAD_SIZE) {
        rist_receiver_data_block_free2(&data_block);
        return AVERROR_EXTERNAL;
    }
    ...
    size = data_block->payload_len;                     /* caller size discarded */
    memcpy(buf, data_block->payload, size);             /* no bound against caller size */
out_free:
    rist_receiver_data_block_free2(&data_block);
    return size;
```

The only length gate is against the protocol maximum (9972), not against the
caller's `size`. The fix commit changes exactly one line, at pinned
`librist.c.1c10bcc2:229`:

```c
-    size = data_block->payload_len;
+    size = FFMIN(data_block->payload_len, size);
```

Release-tag byte checks: `n7.1.3`, `n8.0`, `n8.0.1`, `n8.1`, `n8.1.1` and
`n9.0` carry the unclamped assignment; `n9.0.1`, `n9.0.2`, `n9.1` carry the
clamp. The first release tag observed with the fix is n9.0.1.

## 3. Cheapest local experiment

One C file, no daemon, RIST peer, socket, TLS or async thread. Include the
**complete** verbatim `librist_read()` from each of four pinned blobs
(vulnerable parent, n9.0, fix commit, n9.0.1) in a driver with stubbed
librist/librist types, `URLContext`/`RISTContext`, error/log macros and
`rist_receiver_data_read2()`. Give the function a 4096-byte heap destination
(the async caller cap) and a 9972-byte source payload (the RIST protocol cap)
carrying chosen markers past offset 4096. Fixed and n9.0.1 are fixed controls;
n9.0 is a second vulnerable control; a 4-byte payload is the safe control;
9973 bytes exercises the existing guard in every variant.

## 4. Rung-4 feasibility and risks

Favourable: a single unbounded `memcpy` with a fully controlled length and
source; real caller and protocol bounds are documented in pinned source; the
fixed variant differs by one line. Constraints measured here: plain builds
need an adjacent harness heap object to absorb the overwrite before libc can
observe a corrupted top chunk; ASan faults on the WRITE before any downstream
observation, so chosen bytes are read only in plain builds; the fixed copies
exactly 4096 bytes, so the last in-bounds byte is attacker-controlled and the
adjacent object stays 0xCC. Chosen values are byte patterns, not pointers,
gadgets or a command.

## 5. Observations

- Harness `PASS=66 FAIL=0` three times plus clean `/tmp` replay; normalized
  trace `6c3586c5d5b510b9619431873b157055c97edc32c5b6eda9967eb4feae61629f`.
- Rung 1: 9972-byte RIST payload, 4096-byte caller buffer, 5876 bytes over;
  both numbers come from pinned source lines.
- Rung 2: vulnerable parent and n9.0 return 9972 and copy the chosen bytes;
  fix and n9.0.1 return 4096 and leave the adjacent object's 0xCC pattern
  intact; 9973 bytes is rejected with `RET=-5` in all four variants.
- Rung 3: gcc and clang ASan `heap-buffer-overflow`, `WRITE of size 9972`, at
  pinned `librist.c.7b05d16c:230` in `librist_read`, 0 bytes after the
  4096-byte region; fixed, n9.0.1 and safe inputs clean.
- Rung 4: chosen bytes 0x41/5a/7a/3c/7b/42/7b/41 at offsets
  4096/4113/4120/4128/4136/4144/4152/4160 and deep smear at 5000/9000;
  the adjacent heap object's data is overwritten with 0x5a and 0x7a; gdb at
  pinned line 233 shows `$1 = 9972` with the chosen bytes in the frame versus
  `$1 = 4096` and intact 0xCC in the fixed build.

## 6. Ceiling / handoff

Direct call with stubbed librist/libavformat plumbing; no real `ffmpeg`
process, RIST socket, peer, wire exchange, async thread/ring buffer, TLS/SRP,
attacker sender or event loop; no pointer control, ROP chain, command, marker
side effect or witness verdict. The 20000-byte adjacent sink is a harness
artefact; the neighbours of an actual async ring destination are UNKNOWN.
A dedicated target mind should first build an FFmpeg with librist support and
observe the sink on living bytes with a loopback RIST sender through
`async:rist://`, then determine what the real ring allocation places after the
4096-byte destination before considering any benign marker. Do not relabel
placed heap bytes as remote execution.
