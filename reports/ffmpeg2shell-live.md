# ffmpeg2shell — live-path result (W2, 2026-11-23)

**Result.** The CVE-2026-75143 sink was reproduced in a real FFmpeg n9.0
process, driven by a real librist sender over a loopback RIST wire through
`async:rist://`, with no stubbed librist/libavformat on the receive path.
ASan reports an out-of-bounds `WRITE` from `librist_read()` at pinned
`librist.c:230`; two vulnerable runs fault, a one-line-clamp fixed build and
a safe-input run stay clean. Under gdb the same live process shows
attacker-chosen bytes at offsets 4096, 4113, 4120, 5000 and 9000 past the
4096-byte caller window. This is rung 3 plus scoped rung 4 on **living
bytes**, not remote command execution.

## Builds and pins (all provisioning was read-only source fetch)

- librist: VideoLAN forge `https://code.videolan.org/rist/librist.git`,
  shallow clone HEAD `a911bee8904d88beb1ccd3349ff9a3de1cadc1a6`
  (2026-10-26), project version 0.2.20. Built with meson
  `-Dtest=false -Dbuiltin_cjson=true -Dbuiltin_lz4=true` (builtin mbedtls was
  selected automatically), installed to `live/prefix`. The formerly cited
  GitHub homes (`Meijin-Technologies/librist`, `librist/librist`,
  `FFmpeg/librist`) return 404 in 2026.
- FFmpeg: `https://codeload.github.com/FFmpeg/FFmpeg/tar.gz/refs/tags/n9.0`,
  tarball SHA-256
  `d97647ace36a307f17ba2bca052d68937487bed8682e1eb9b6737076a9c442b7`,
  reported commit `222c489`. Configured with `--toolchain=clang-asan
  --enable-librist --disable-everything
  --enable-protocol=async,librist,file,pipe --enable-demuxer=data
  --enable-muxer=null --enable-filter=anull --disable-doc
  --disable-autodetect`. Note the protocol config symbol is `librist`, not
  `rist`. Build rc 0 at 2026-11-23T08:01:24Z.
- Fixed binary: the same source tree with `librist.c:229` changed from
  `size = data_block->payload_len;` to
  `size = FFMIN(data_block->payload_len, size);`, i.e. upstream fix commit
  `1c10bcc2` as pinned in `lab/frontier/ffmpeg2shell/PROVENANCE.md`.
- Sender: `lab/frontier/ffmpeg2shell/live/rist_sender_live.c`, SHA-256
  `a87e97b47b3aee36d09709483b1619733fe5365c554fbe2be777d49b70a02371`.
  It calls `rist_sender_create`, `rist_peer_config_defaults_set`,
  `rist_parse_address2`, `rist_peer_create`, `rist_start` and
  `rist_sender_data_write` directly against the built library. All traffic
  is to 127.0.0.1; nothing external was contacted as a test.

## Geometry correction found on the live path

`librist_sender_data_write()` rejects `payload_len > RIST_MAX_PACKET_SIZE -
32 = 9968`, four bytes below FFmpeg's receive gate `MAX_PAYLOAD_SIZE =
10000-28 = 9972`. A stock librist sender therefore delivers 9968 bytes, not
9972; this is still 5872 bytes past the async caller's 4096-byte window.
The 9972 number in the direct-call harness is the protocol receive ceiling,
not a payload a stock sender can emit.

More importantly, the async destination is **not** a standalone 4096-byte
heap object. `async.c:88` allocates one 8388608-byte FIFO
(`av_fifo_alloc2(BUFFER_CAPACITY + READ_BACK_CAPACITY, 1, 0)`);
`async.c:235` asks for 4096 bytes and `fifo.c:167` hands
`librist_read()` a pointer `wptr` into that 8 MiB allocation. The first
~2048 reads write 9968 bytes entirely inside the ring and ASan stays
silent. The fault occurs when `wptr` reaches the allocation's last 4096
bytes: `len = FFMIN(nb_elems - offset_w, to_write)` becomes small, but
`librist_read()` ignores it and writes the full block across the end. The
frontier's "5876-byte overflow past a 4096-byte heap object" is a harness
model of the intended window; on a live consumer the measured claim is an
out-of-bounds ring write at the wrap boundary after roughly 8 MiB of
attacker-streamed data. No live adjacent heap object with metadata was
identified.

## Experiment matrix

Receiver (all cases):
`env LD_LIBRARY_PATH=live/prefix/lib ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
<ffprobe-binary> -loglevel verbose -f data -i 'async:rist://@:5004' -show_packets`.

Sender (all cases):
`env LD_LIBRARY_PATH=live/prefix/lib ./rist_sender_live rist://127.0.0.1:5004 2200 <len>`.

| Case | Binary | Blocks x bytes | Result |
|---|---|---|---|
| vuln-1 | `ffprobe-vuln` | 2200 x 9968 | ASan heap-buffer-overflow, `WRITE of size 9968`, `ffprobe rc=1` |
| vuln-2 | `ffprobe-vuln` | 2200 x 9968 | same fault reproduced, `ffprobe rc=1` |
| fixed | `ffprobe-fixed` (FFMIN clamp) | 2200 x 9968 | ASan-clean, 8800 packets shown, survived to timeout `rc=124` |
| safe input | `ffprobe-vuln` | 2200 x 512 | ASan-clean, survived to timeout `rc=124` |

Sender logs show `sent 2200 blocks ... 0 failures` in all four cases.

## ASan evidence (vuln-1)

`live/evidence/live-vuln-asan-1.log`, thread T2 (async):

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 9968 at 0x7c34ae9ff800 thread T2 (async)
0x7c34ae9ff800 is located 0 bytes after 8388608-byte region
```

Symbolized with `addr2line -e ffprobe_g-vuln` (unstripped build):

| Frame | Symbol | Source |
|---|---|---|
| write | `librist_read` | `libavformat/librist.c:230` |
| 1 | `ffurl_read2` | `libavformat/avio.c:522` |
| 2 | `ffurl_read` | `libavformat/url.h:183` |
| 3 | `fifo_write_common` | `libavutil/fifo.c:167` |
| 4 | `async_buffer_task` | `libavformat/async.c:152` |
| allocation | `av_fifo_alloc2` | `libavutil/fifo.c:57`, from `async_open` `async.c:88` |

The write frame is the async thread; the allocation happened in the main
thread. This is the same chain the frontier pinned from source, now observed
on running bytes.

## Chosen-byte readback (live, under gdb)

`live/evidence/live-vuln-gdb-chosen-bytes.log`. The breakpoint was placed at
`librist_read+0x1ba`, the instruction immediately after `__asan_memcpy`
returns, to avoid the EAGAIN paths that jump past the copy. At the hit:

```
librist_read (...) at libavformat/librist.c:230, size=9968
frame 1: retry_transfer_wrapper (..., buf=0x7ffff47ff800 'Z' <repeats 200 times>..., size=4096)
0x7ffff47ff800: 0x5a ...            (destination start)
0x7ffff4800800 = buf+4096: 0x41 0x5a ...
0x7ffff4800811 = buf+4113: 0x7a ... 0x3c at buf+4120
0x7ffff4800b88 = buf+5000: 0x42 ...
0x7ffff4801b28 = buf+9000: 0x63 ...
```

These are the marker bytes placed by `rist_sender_live.c`; the caller asked
for 4096 bytes, and the live ring holds the attacker's bytes well past that
window. This is placement in a real consumer's memory, not in the harness's
20000-byte sink. It is still byte placement, not a pointer or a command.

## Ceiling / not claimed

- No pointer control, ROP, function-pointer overwrite, chosen-address write
  or command execution. No marker file or other external side effect.
- The 8 MiB ring's neighbours were not mapped to useful state; the live
  out-of-bounds write is at an allocator-owned boundary, not into a named
  adjacent object.
- No independent witness replay of this live work yet. The prior witness
  verdict #2384 covers only the direct-call harness (rungs 1-4 at that
  labeled scope).
- Main profile without encryption was used because FFmpeg does not expose
  its `rist_profile` AVOption through the URL query (librist's own parser
  reports `Unknown or invalid parameter rist_profile`); the receive path and
  the vulnerable function are the same.
- Reproducing the ASan fault needs ~8 MiB of streamed data to walk the ring
  write pointer to its end; a single oversized packet alone does not fault
  ASan on the live consumer.

## Failed attempts and negatives (preserved)

- The installed librist `ristsender` CLI fails at startup with
  `undefined symbol: rist_tun_read` under this library; the installed tool
  and the freshly built one have different hashes. Replaced by the direct
  API sender above.
- A 9972-byte sender block is rejected by librist with `write ... -1` on
  every attempt (900/900 failures); corrected to 9968 after reading
  `rist.c:633`.
- The first sender build had an uninitialized `struct rist_peer_config`,
  giving `Invalid encryption key length: 32765`; corrected by zeroing it.
- gdb breakpoints at pinned source lines 233/234 caught EAGAIN paths that
  jump past the memcpy (`mov $0xfffffff5,%r15d; jmp ...` in the
  disassembly), so the first three readback attempts showed untouched 0xBE
  fill. Breaking after the `memcpy` call gave the readback above.

## Re-run

The built artifacts and scripts live in
`lab/frontier/ffmpeg2shell/live/`. `live/run-cases.sh` runs the four cases
against already-built binaries; rebuilding from source needs the fetches and
configure/make commands quoted above. Check: vuln ASan `WRITE of size 9968`
at `librist.c:230`, fixed and safe clean.
