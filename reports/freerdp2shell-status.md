# Freerdp2Shell status

Admitted by the operator 2026-11-20 ~19:32Z under standing approval #6;
handed off from frontier ~19:2xZ. Dedicated two-pane window (inner socket,
window 18) and restorer registry entry are live; seed wall at
`.mishe-tauftauf/walls/freerdp2shell.md`, charter at
`.mishe-tauftauf/charters/freerdp2shell.md`, and the docs/task.md entry is
committed. Wake trigger units and the presentation.json `active` entry are
still owed from the person's full-flag sync (docs/runtime-pin.md — never a
bare `mishe sync`). Frontier re-ran the committed harness from clean HEAD;
the operator re-ran it at 19:30Z: `bash lab/frontier/freerdp2shell/run.sh`
prints `ALL CHECKS PASS`, rc 0, twice; digests `d0a31487…` / `c5186500…`.

## Target

FreeRDP server-side rdpsnd channel `rdpsnd_server_select_format()` integer
wraparound, GHSA-3m9q-g533-rqjq / CVE-2026-114045 (CWE-122 via CWE-190,
CVSS 3.1 8.8 High post-auth / 9.8 Critical no-auth),
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`. Advisory boundary: affected
`master <= 8ec6d3923b` and stable `<= 3.32.0`; fixed `>= 3.32.1`. Lineage: a
bypass of the CVE-2026-63117 fix (`b7ca093`). Default posture is
post-authentication (PR:L); only no-auth RDP deployments reach 9.8.

## Mechanism and reproduction
Line numbers for `rdpsnd_main.c` below are raw-file lines at the named tag
(the earlier reader-displayed numbers were +6).

- Parse-time check (`rdpsnd_main.c:252-259`, 3.32.0) enforces only
  `nBlockAlign >= 4` for DVI_ADPCM, never `nBlockAlign >= 4*nChannels`, so a
  client sends `nBlockAlign=4, nChannels=2` in an `SNDC_FORMATS` record.
- `select_format()` (3.32.0, :409-418) computes
  `bs = 4ULL*(4 - 4ULL*2) = 0xFFFFFFFFFFFFFFF0`, all `WINPR_ASSERT`s pass,
  `out_frames` becomes that wrapped value, `out_buffer_size` wraps to
  `0xFFFFFFFFFFFFFFC0`, `realloc` fails, and `out_frames` is **not rolled back**
  (:446-451).
- `send_samples()` (:765-785) then `CopyMemory`s client sample bytes into the
  still-8820-byte `out_buffer`; `out_pending_frames` never reaches the huge
  `out_frames`, so successive calls append at monotonically advancing offsets
  — an unbounded, sequential, attacker-controlled heap write.
- Harness (pinned digests above): rung 1 `rc2=2 out_frames=0xfffffffffffffff0
  realloc_failed=1`, `oob_writes=7564 first_oob=8820 last_oob=16383`; rung 2
  chosen bytes `ab`/`cd` land at OOB offsets 8820/12000; rung 3 ASan
  `heap-buffer-overflow`, `WRITE of size 16384`, `0 bytes after an 8820-byte
  region`, from `memcpy` via `send_samples`; rung 4 two calls place `de` at
  offset 8820 and `ad` at 21384 with `out_pending_frames=8192`; benign and
  3.32.1-guard controls show `oob_writes=0`; five traces byte-identical.

## Real-library replay (wake 3, 2026-11-20 22:42Z)

The advisory in-process PoC was replayed against a source-built FreeRDP
3.32.0 (`d27a4f7c1c63b62a5e60e5d939ad116cfb58ffc1`) with gcc ASan/UBSan,
not the extracted harness. Harness: `lab/freerdp2shell-src/`
(`PocRdpsndOverflow.c`, `PocPcmControl.c`, `run.sh`, captured `*.txt`).
`bash lab/freerdp2shell-src/run.sh` prints `ALL REAL-LIBRARY CHECKS PASS`,
rc 0, with a prebuilt `/tmp/fr-wake2/build3320`.

Observed on the vulnerable library (pinned in
`lab/freerdp2shell-src/vuln_real_library_asan.txt`):

```
[rdpsnd_server_select_format]: realloc failed!
SelectFormat rc=12  out_frames=0xfffffffffffffff0
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 16384 ... 0 bytes after an 8820-byte region
  rdpsnd_server_send_samples channels/rdpsnd/server/rdpsnd_main.c:770
allocated by realloc in rdpsnd_server_select_format rdpsnd_main.c:444
```

This is rung 3 on real library bytes. The benign PCM control exits rc 0,
`out_frames=0x89d` (8820 bytes), no ASan report. A third control patched the
3.32.1 division guard (`nBlockAlign / 4ull < nChannels` at 3.32.1 :409) into
the scratch 3.32.0 source, rebuilt only `libfreerdp-server3.so`, and reran
the same binary: no ASan heap overflow, `out_frames=0x89d`; it aborts later
in an unrelated `Stream_ResetPosition` assert because the in-process harness
has no channel. The vulnerable library was restored and the wrap reproduced
again, confirming the guard was the discriminator.

## Real SNDC_FORMATS parse path (wake 3, 22:46Z)

`PocRdpsndWire.c` compiles the real 3.32.0 `rdpsnd_main.c` source into the
test translation unit so the static `rdpsnd_server_recv_formats()` parser is
the real code, and feeds it a crafted 20-byte `SNDC_FORMATS` header followed
by two `audio_format_write()` records (benign PCM, then DVI_ADPCM
`nChannels=2, nBlockAlign=4, cbSize=2`). Captured in
`lab/freerdp2shell-src/wire_parse_asan.txt`:

```
recv_formats rc=0 nformats=2
parsed[1]: tag=17 channels=2 blockalign=4 cbsize=2
SelectFormat rc=12 out_frames=0xfffffffffffffff0
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 16384 ... 0 bytes after an 8820-byte region
  rdpsnd_server_send_samples rdpsnd_main.c:770
```

The real parser admits the inconsistent format (only the scalar
`nBlockAlign >= 4` floor applies), and the wrap plus overwrite follow on the
parsed struct. This is still in-process injection of a PDU into the real
parser — no virtual-channel transport, RDP session or auth gate.

## Chosen-byte rung 4 on real bytes (wake 4, 2026-11-20 23:01Z)

`PocRdpsndChosenBytes.c` compiles the real 3.32.0 `rdpsnd_main.c` into the
test translation unit, feeds a crafted `SNDC_FORMATS` PDU through the real
`rdpsnd_server_recv_formats()` parser, selects benign PCM then the malicious
ADPCM format, and makes two `SendSamples` calls with distinguishable client
buffers. It is built **without** sanitizers: ASan aborts on the first OOB
write and cannot observe the second call. A scratch plain build of the same
source is used; the ASan results above remain the corruption evidence.

Captured in `lab/freerdp2shell-src/chosen_bytes_real_library.txt`:

```
recv_formats rc=0 nformats=2
parsed[1]: tag=17 channels=2 blockalign=4 cbsize=2
SelectFormat rc=12 out_frames=0xfffffffffffffff0 out_buffer_size=8820
readback offset 8819  = 11 (last in-bounds byte)
readback offset 8820  = de (client marker, call 1, first OOB byte)
readback offset 16384 = 22 (call 2 start)
readback offset 21384 = ad (client marker, call 2)
out_pending_frames=8192 out_frames=0xfffffffffffffff0 (never reached)
[rung4] RESULT=PASS
```

The process exits 0 via `_exit()` after flushing: normal teardown frees the
deliberately corrupted heap and faults. Fixed-source control: the same PoC
compiled with the 3.32.1 division guard inserted exits 3 with
`out_frames=0x89d` and no wrap or chosen-byte write. `run.sh` now provisions
both builds (and passes `-DWITH_FFMPEG=OFF`, `-DWITH_SWSCALE=OFF`,
`-DCHANNEL_URBDRC=OFF`, `-DWITH_CUPS=OFF`, `-DWITH_FUSE=OFF` so a fresh host
can configure) and checks all four PoCs; full run rc 0. Clean-room check at
23:28Z: `FREERDP_WORK=/tmp/fr-wake4-fresh bash lab/freerdp2shell-src/run.sh`
cloned 3.32.0, built both variants from scratch and printed
`ALL REAL-LIBRARY CHECKS PASS`, rc 0 (ASan build needed an incremental resume
after the harness's 20-minute foreground cap; the resumed build and runner
took 88s and 39s).

## Real channel message dispatch (wake 5, 2026-11-20 23:50Z)

`PocRdpsndChannelDispatch.c` goes one layer above the direct-parser PoCs. It
registers a WTS API table whose `pVirtualChannelRead` serves a scripted
in-memory byte stream in 20-byte chunks, frames a complete `SNDC_FORMATS` PDU
(4-byte `msgType`/`bPad`/`bodySize` header plus body) and calls the real
exported `rdpsnd_server_handle_messages()` (`rdpsnd_main.c:1204-1298`). The
real dispatcher reassembles the body across reads, demultiplexes `msgType=7`
at :1274 and invokes the real `rdpsnd_server_recv_formats()`.

Captured in `lab/freerdp2shell-src/dispatch_chosen.txt`:

```
handle_header rc=0 handle_body rc=0 reads=4 msgType=7 nformats=2
parsed[1]: tag=17 channels=2 blockalign=4 cbsize=2
SelectFormat rc=12 out_frames=0xfffffffffffffff0 out_buffer_size=8820
readback offset 8819=11 offset 8820=de offset 21384=ad
out_pending_frames=8192 out_frames=0xfffffffffffffff0
[dispatch] chosen RESULT=PASS
```

The ASan build of the same PoC (`dispatch_asan.txt`) reports `WRITE of size
16384`, `0 bytes after 8820-byte region`, frame
`rdpsnd_server_send_samples rdpsnd_main.c:770`. A benign one-record PDU
through the same dispatcher (`dispatch_benign.txt`) yields
`out_frames=0x89d` and no chosen-byte write. `run.sh` now checks all three;
`bash lab/freerdp2shell-src/run.sh` prints `ALL REAL-LIBRARY CHECKS PASS`,
rc 0.

The WTS read callback is a stub: this is not a live RDP session, virtual
channel transport, network path or auth gate. PDU framing and server message
dispatch are now evidenced; those remaining layers are still UNKNOWN.

## Evidence boundary

Rungs 1/2/3 established; rung 4 PASS with client-chosen bytes at chosen OOB
offsets **on real library bytes through the real SNDC_FORMATS parser and the
real `rdpsnd_server_handle_messages()` dispatcher**, but still in-process with
a stubbed WTS read callback. The write is sequential and unbounded; no pointer
control or specific heap object is targeted. Live FreeRDP process, real
virtual-channel transport, RDP session, stock allocator layout, network
reachability and the auth gate remain UNKNOWN. No off-loopback probe. Default
posture is post-auth (PR:L, CVSS 8.8); only no-auth deployments reach 9.8.

Brief: `reports/frontier-freerdp2shell.md`; harness:
`lab/frontier/freerdp2shell/{rdpsnd_overflow.c,run.sh}`. Witness replay
requested; author report is not acceptance.
