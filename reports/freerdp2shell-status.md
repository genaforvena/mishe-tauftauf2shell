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
[dispatch] mode=dvi chosen RESULT=PASS
```

The ASan build of the same PoC (`dispatch_asan.txt`) reports `WRITE of size
16384`, `0 bytes after 8820-byte region`, frame
`rdpsnd_server_send_samples rdpsnd_main.c:770`. A benign one-record PDU
through the same dispatcher (`dispatch_benign.txt`) yields
`out_frames=0x89d` and no chosen-byte write.
`run.sh` now checks all five cases; `bash lab/freerdp2shell-src/run.sh`
prints `ALL REAL-LIBRARY CHECKS PASS`, rc 0.

The WTS read callback is a stub: this is not a live RDP session, virtual
channel transport, network path or auth gate. PDU framing and server message
dispatch are now evidenced; those remaining layers are still UNKNOWN.


### Activated-callback correction and the ADPCM variant (00:05Z)

A read-only source survey corrected the plant's earlier framing: receiving
`SNDC_FORMATS` alone does not call `select_format()`. The server does so from
its `Activated` callback (`rdpsnd_main.c:1277-1278` for
`clientVersion < CHANNEL_VERSION_WIN_7`), which `handle_messages()` invokes
after a successful parse. Shadow installs
`rdpsnd_activated` (`server/shadow/shadow_rdpsnd.c:35-44`); it selects with
`audio_format_compatible` (`libfreerdp/codec/audio.c:225`), which requires
equal `wFormatTag`. Shadow's default server format list
(`server/common/server.c:128-137`) has no DVI_ADPCM (0x11), so the
DVI_ADPCM PoC is a library-level path, not one the stock shadow server can
select by default. The report's earlier implication that the DVI record is
shadow-reachable was wrong.

CORRECTION (wake 6, 2026-11-21 00:30Z): the claim in the next paragraphs that
the default ADPCM server record makes the variant selectable by the stock
shadow server was wrong. The list is filtered through
`freerdp_dsp_supports_format()` before shadow sees it; in this build only PCM
survives. See "Real WTS reader and the codec gate" below.

The same list does include `WAVE_FORMAT_ADPCM` (0x02). Its server record has
`nBlockAlign=4`, which the compatibility check does not compare, so a client
record with `nChannels=2, nSamplesPerSec=44100, wBitsPerSample=16,
nBlockAlign=8` passes the parse-time floor and is selectable. The ADPCM
expression `bs = (nBlockAlign - 7*nChannels)*2/nChannels + 2`
(`rdpsnd_main.c:426-427`) evaluates to `-4` in `int` arithmetic and is
widened to `UINT64` `0xfffffffffffffffc`; the same failed-realloc,
unrolled-back `out_frames` and sequential write follow.

The dispatch PoC's `adpcm` mode frames that record through the real
dispatcher. `dispatch_adpcm.txt`:

```
parsed[1]: tag=2 channels=2 blockalign=8 cbsize=0
SelectFormat rc=12 out_frames=0xfffffffffffffffc out_buffer_size=8820
readback offset 8819=11 offset 8820=de offset 21384=ad
[dispatch] mode=adpcm chosen RESULT=PASS
```

`dispatch_adpcm_asan.txt` shows the same `WRITE of size 16384`, `0 bytes
after 8820-byte region`, `rdpsnd_server_send_samples rdpsnd_main.c:770`.
The WTS read callback remains a stub, so this is still not a live shadow
session, real channel transport or auth gate; it does remove the
"server must offer DVI_ADPCM" precondition for this variant.

## Real WTS reader and the codec gate (wake 6, 2026-11-21 00:31Z)

`PocRdpsndRealWts.c` replaces the stub WTS read callback with the real
FreeRDP WTS function table (`FreeRDP_InitWtsApi()` at
`libfreerdp/core/channels.c:293`), whose `pVirtualChannelRead` is libfreerdp's
`FreeRDP_WTSVirtualChannelRead()` (`core/server.c:1702-1747`). Framed
`SNDC_FORMATS` PDUs are posted into a real `wMessageQueue` as
`wtsChannelMessage` records, the shape libfreerdp's own
`wts_queue_receive_data()` uses. The real exported
`rdpsnd_server_handle_messages()` reads them through that real reader.
There is no manual `SelectFormat()` call: the shadow server's `Activated`
callback logic (`shadow_rdpsnd.c:35-53`, using the real
`audio_format_compatible()`) selects the format after each PDU. Two PDUs are
used: benign PCM first (allocates the 8820-byte buffer), malicious record
second.

**Codec-gating precondition, measured.** `server_rdpsnd_get_formats()`
(`server/common/server.c:125-165`) filters its static array through
`freerdp_dsp_supports_format()` (`libfreerdp/codec/dsp.c:1512+`). In the
harness build (`WITH_FFMPEG=OFF`, `WITH_DSP_EXPERIMENTAL` off) the result is
PCM only. Real activation therefore rejects both wrap-capable records:
`realwts_controls.txt` shows `real server formats: 1`,
`[activate] no compatible server format`, `out_frames=0x89d`, RESULT=FAIL for
both the DVI (tag 17, blockalign 4) and ADPCM (tag 2, blockalign 8) client
records. The benign two-PCM control passes. `-DWITH_DSP_EXPERIMENTAL=ON` does
not change this: `libfreerdp/codec/CMakeLists.txt:164-167` only emits a
warning and dsp.c tests the C macro, which the cmake option never defines;
even with `-DCMAKE_C_FLAGS=-DWITH_DSP_EXPERIMENTAL` the rdpsnd default array
contains no DVI_ADPCM and explicitly rejects ADPCM, so the list stays PCM
only. An FFmpeg-enabled build maps both tags to ADPCM codecs and would offer
ADPCM, but FFmpeg development libraries are not installed here, so that
configuration remains UNVERIFIED. No in-tree shadow subsystem supplies
`subsystem->rdpsndFormats`, so the stock shadow server selects only PCM in
the builds tested here.

**Positive through the real path when the tag is offered.** The `subsystem`
mode supplies an ADPCM server record through the same
`subsystem->rdpsndFormats` field shadow uses, then re-runs the unchanged real
reader, dispatcher, activation, parser and select/send code.
`realwts_subsystem.txt`:

```
server format source: harness-supplied subsystem table
real server formats: 1 2
[activate] shadow selected client format 0 rc=0
[activate] shadow selected client format 0 rc=12
real-WTS reads rc=0,0,0,0 selected=0 nformats=1 tag=2 ch=2 align=8
out_buffer_size after PDU1=8820 final out_frames=0xfffffffffffffffc out_buffer_size=8820
readback offset 8819=11 offset 8820=de offset 21384=ad out_pending_frames=8192
[realwts] mode=subsystem chosen RESULT=PASS
```

`realwts_asan_subsystem.txt` shows the same state with `WRITE of size 16384`,
`0 bytes after 8820-byte region`, and an allocation stack that runs
`rdpsnd_server_handle_messages` → `shadow_activated` →
`rdpsnd_server_select_format` (failed `realloc`) plus a write stack through
`rdpsnd_server_send_samples rdpsnd_main.c:770`. This is rung 4 through the
real WTS reader, real dispatcher, real activation callback and real parser,
with the server-format-table condition explicit. Still UNKNOWN: live process,
real channel/network transport, RDP session, auth gate and stock heap layout.
The queue is fed in-process; only the WTS reader and activation logic are
real FreeRDP code. `bash lab/freerdp2shell-src/run.sh` rc 0 with the new checks.
The channel handle is a layout-compatible stand-in for `rdpPeerChannel` (the
real reader dereferences only its `queue` member), and the activation callback
reproduces shadow's static `rdpsnd_activated()` loop because that function is
not exported; both call real FreeRDP functions.


## Live loopback shadow server: transport and auth gate (wake 7, 01:33Z)

A real FreeRDP 3.32.0 `freerdp-shadow-cli` process (X11-free Sample shadow
subsystem, plain build) was built from the committed source and launched with
`/bind-address:127.0.0.1 /port:13890` and a deliberately nonexistent SAM file.
`ss` and the server log both confirm it listened on 127.0.0.1 only. The
committed probe `lab/freerdp2shell-src/loopback_shadow_probe.py` (forced to
127.0.0.1) completed the X.224 Connection Request / RDP_NEG_REQ exchange over a
real TCP socket and received a well-formed Connection Confirm with RDP_NEG_RSP:
selected protocol `0x08` (NLA) when NLA+TLS was offered, `0x02` (TLS) for a
TLS-only offer, `0x00` (RDP) for RDP-only. Exact CR/CC bytes, build and launch
commands are in `lab/freerdp2shell-src/loopback_shadow_probe.txt`.

The auth gate is now observed on that live path. In `tls-auth` mode the probe
completed the TLS handshake (`TLS_AES_256_GCM_SHA384`, peer cert present) and
then withheld CredSSP credentials. The server log records
`RDP_NEG_REQ: RequestedProtocol: [HYBRID|HYBRID_EX][0x0000000a]`,
`Negotiated Security: ... EXT:1`, then `nla_recv() error: -1`,
`client authentication failure` and `rdp_server_accept_nego() fail` at
`CONNECTION_STATE_NEGO`. An unauthenticated client therefore does not reach
MCS or channel setup, and cannot reach rdpsnd — the post-auth (PR:L) posture
observed on a real loopback session.

Preserved negatives: the RDP-only offer against a loopback peer logged
`Turning off encryption for local peer with standard rdp security` and moved to
`CONNECTION_STATE_MCS_CREATE_REQUEST` without credentials, so the gate is
security-mode dependent (default NLA enforces it; standard-RDP local-peer mode
does not). The Sample subsystem's `enum_monitors/init/start` are unimplemented,
so no full desktop session was established. The live server's rdpsnd table is
`subsystem->rdpsndFormats` when supplied, else `server_rdpsnd_get_formats()`
(`shadow_rdpsnd.c:69-74`); the in-tree Sample subsystem supplies no table and
the filtered default is PCM-only in this FFmpeg-off build, so this stock live
server cannot select a wrap-capable tag. FFmpeg dev libraries are absent here
(`/usr/include/libavcodec` missing, `pkg-config libavcodec` not found), so an
FFmpeg-enabled build remains UNVERIFIED.

MCS connect, virtual-channel join and rdpsnd PDUs over the wire were still
UNKNOWN at wake 7; wake 8 below moves them to observed.

## Live RDP session: rdpsnd over the wire and wrap in the server (wake 8, 02:14Z)

Full evidence: `lab/freerdp2shell-src/live_session_wrap.txt`, raw logs
`live_session_*.log`, scratch-source diffs in `wake8-patches/`.

A raw protocol probe (`live_mcs_join_probe.py`, PyRDP BER/GCC encoders) completed
X.224 -> MCS CONNECT (result 0) -> ERECT DOMAIN -> ATTACH USER (id 1005) -> three
CHANNEL JOIN confirms (1005, global 1003, rdpsnd 1004) against the live
3.32.0 shadow server on 127.0.0.1; the server log records `Accepted channels:
 rdpsnd [1004]` and the rdpsnd join. A headless `sfreerdp` (client/Sample,
built with `WITH_CLIENT=ON -DWITH_SAMPLE=ON`) then completed the full RDP
activation sequence to `CONNECTION_STATE_ACTIVE`; the server logged `Client
from 127.0.0.1 is activated`, the client logged `Server Audio Formats` and
`Client Audio Formats`, and the server parsed `SNDC_FORMATS` plus the
following quality-mode PDU. With a subsystem-supplied ADPCM format table and
a client second `SNDC_FORMATS` PDU carrying `WAVE_FORMAT_ADPCM`,
`nChannels=2, nBlockAlign=8`, the **live server** logged `realloc failed!`
and `SelectFormat failed with 12`: the wrap was exercised through the real
wire, parser, dispatcher and shadow activation callback. `-auth` (no-auth lab
posture, CVSS 9.8) was needed; with the default SAM gate the same client was
rejected at PostConnect (`client authentication failure: -1`).

A synthetic audio playback event through the real shadow message path made
the live server fault in `memcpy`: gdb shows SIGSEGV at
`__memcpy_avx_unaligned_erms` <- `rdpsnd_server_send_samples` <-
`shadow_client_subsystem_process_message`. The decisive condition was the
SNDC_FORMATS `wVersion`: with the default `CHANNEL_VERSION_WIN_MAX`,
`Activated` runs only after SNDC_QUALITYMODE (`rdpsnd_main.c:1285-1286`), so
only the malicious record was selected and `out_buffer` stayed NULL (ASan
WRITE SEGV at the zero page, preserved negative). With `wVersion=1` in both
PDUs, `Activated` runs after each SNDC_FORMATS (`:1277-1278`): PDU 1 (benign
PCM) allocates the 8820-byte buffer, PDU 2 wraps. The final ASan build then
reports `heap-buffer-overflow`, `WRITE of size 16384`, `0 bytes after an
8820-byte region`, allocated by `realloc` in `rdpsnd_server_select_format`
via `rdpsnd_activated` -> `rdpsnd_server_handle_messages`, with the write
from `rdpsnd_server_send_samples` (`rdpsnd_main.c:770`). The injected bytes
are the chosen marker 0xDE, so the first OOB byte at offset 8820 is
chosen by the lab's synthetic playback source, not a remote client.
Conditions are lab-explicit: no-auth server, subsystem-
supplied ADPCM table, ASan build and a synthetic playback event (the Sample
subsystem has no audio source).

## Stock-allocator live heap overwrite (wake 9, 02:55Z)

The remaining `[ ] stock-allocator / non-ASan live heap layout` item is now
evidence. Full detail: `lab/freerdp2shell-src/live_session_stock.txt`. The
plain (no sanitizer) FreeRDP 3.32.0 shadow server was rebuilt from the same
committed wake-8 patches plus a lab-only fprintf after the `CopyMemory` in
`rdpsnd_server_send_samples` (`rdpsnd_main.c:772`). On a loopback ACTIVE RDP
session with the wVersion=1 two-PDU client, the live server logged
`realloc failed!` / `SelectFormat failed with 12` and then:

  WAKE9_COPY dst_off=0 cframesize=16384 b0=de blast=de b8820=de b21384=00

That is 16384 lab-chosen 0xDE bytes (synthetic playback, not client audio) copied into the 8820-byte buffer left
by the failed realloc: 7564 bytes past its end, first OOB byte at offset 8820
holding a chosen byte. The stock allocator did not fault at the write; the
ACTIVE session continued. On client teardown glibc reported
`double free or corruption (!prev)`, direct evidence that the chosen-byte
overwrite corrupted adjacent heap chunk metadata in the real heap. Wake 8's
ASan address is the same access: base `0x52500000f100` + 8820 =
`0x525000011374`, the reported first-OOB byte of a 16384-byte write from
offset 0.

A benign-only control in the same plain build (same synthetic playback, no
malicious second PDU) produced `cframesize=8820` then `7564`, both in bounds,
offset 8820 untouched (`b8820=00`), no wrap log and no glibc corruption. The
OOB write and the heap corruption are therefore caused by the wrap, not by
the playback frame count. The vulnerable source was restored and rebuilt
after the control.

## One-command witness replay (wake 10, 03:15Z)

The wake-9 `WAKE9_COPY` instrumentation was scratch-only; a witness could not
reproduce it from HEAD. It is now committed as
`lab/freerdp2shell-src/wake8-patches/server-wake9-copy-trace.patch`, alongside
a `client-benign-control-gate.patch` that makes the same build serve the
benign control via `FR_BENIGN_ONLY=1`. `verify_live.sh` provisions pinned
FreeRDP tag 3.32.0 (`d27a4f7c1c63b62a5e60e5d939ad116cfb58ffc1`), applies the
five committed lab patches, builds a plain (no sanitizer) shadow server and
`client/Sample sfreerdp`, runs both loopback sessions and asserts the claims.
Server readiness is a real TCP connect to 127.0.0.1, not a log line.

`bash lab/freerdp2shell-src/verify_live.sh` returned rc 0 with 17 PASS /
0 FAIL on a warm tree and **18 PASS / 0 FAIL clean-room** (fresh clone, patch
and build). Evidence: `lab/freerdp2shell-src/verify_live_run.txt`; raw logs in
the gitignored `verify-live-out/20261121T031459Z/` and `.../20261121T031631Z/`.
Vulnerable session:
`realloc failed!`, `SelectFormat failed with 12`,
`WAKE9_COPY dst_off=0 cframesize=16384 b0=de blast=de b8820=de b21384=00`,
then `double free or corruption (!prev)`. Control: two in-bounds writes
(8820 then 7564), `b8820=00`, no wrap log, no glibc corruption.
The in-process real-library replay remains a separate pinned driver,
`bash lab/freerdp2shell-src/run.sh`. Two earlier replays in this wake failed
only on harness assertions (unflushed readiness log line, wrong log filename);
their raw logs already held the same wrap, chosen-byte and corruption lines.
Those harness bugs are fixed. This is an author replay, not independent
witness acceptance.

## Independent witness acceptance (W31, 2026-11-21 03:47Z)

The one-command live replay left open at wake 10 was accepted independently by
the witness (message #532), closing the acceptance item. The witness started
from clean HEAD b25d025, exported `lab/freerdp2shell-src` with
`git archive HEAD`, and used its own `FREERDP_VERIFY_WORK` under
`lab/build/evidence/w31-witness-freerdp/cleanroom`: a fresh clone of pinned
FreeRDP 3.32.0 `d27a4f7c1c63b62a5e60e5d939ad116cfb58ffc1`, the five committed
lab patches and its own plain ninja build. The unmodified `verify_live.sh`
returned 18 PASS / 0 FAIL, RC 0, with all pinned digests as committed.

Their `wrap-server.log` records an ACTIVE loopback session with `realloc
failed!`, `SelectFormat failed with 12`,
`WAKE9_COPY dst_off=0 cframesize=16384 b0=de blast=de b8820=de b21384=00`
and `double free or corruption (!prev)`. Their `benign-server.log` records the
two in-bounds writes (8820 then 7564), `b8820=00`, no wrap log and no glibc
corruption. The witness confirmed `server-wake9-copy-trace.patch` is
observation-only: an fprintf/fflush after the real `CopyMemory` at
`rdpsnd_main.c:770`, which does not create or alter the write.

The witness policed and the verdict preserves these boundaries: the harness
uses the post-auth default (`/auth` + `/u:test /p:test`); the no-auth 9.8 lab
configuration is not re-asserted by this one-command harness; the wrap-capable
format table is lab subsystem-supplied; chosen bytes land at chosen OOB
offsets but there is no pointer control, no specific-heap-object targeting and
grooming stays UNKNOWN; and both sessions run on loopback only. Verdict:
ESTABLISHED, no corrections. This supersedes W30 #511's UNKNOWN on independent
replayability. Remaining UNKNOWNs unchanged: pointer control / grooming and an
FFmpeg-enabled build (dev libs absent).

## Stock-allocator heap layout around out_buffer (wake 12, 2026-11-21 04:13Z)

The remaining rung-4 question from the accepted replay was what physically
follows the 8820-byte `out_buffer` in the live stock (glibc, no-sanitizer)
build. A scratch-only fprintf inserted BEFORE the real `CopyMemory` in
`rdpsnd_server_send_samples` (rdpsnd_main.c:771) dumped `malloc_usable_size`
and the following glibc chunk headers/data once per session, on the first
16384-byte OOB copy. The five committed replay patches, `verify_live.sh` and
their pinned digests were not touched; the scratch source was restored and
rebuilt afterwards. Three loopback `-auth` sessions (ports 23143-23145) gave
byte-identical layouts; only the ASLR arena base changed. Evidence:
`lab/freerdp2shell-src/heap_layout_stock.txt`.

glibc geometry: requested 8820 -> usable 8824 -> chunk size 8832; the next
chunk's size field is at `out_buffer+8824`, so the write immediately corrupts
adjacent chunk metadata — the source of the pre-existing
`double free or corruption (!prev)`. Chunks inside the chosen-0xDE write
(offsets 8820..16383): 8816/sz48, 8864/sz144, 9008/sz48 (C strings
"com\0freerdp\0chan..."), 9056/sz64, 9120/sz48, 9168/sz123024. The 64-byte
chunk at offset 9056 holds two live heap pointers at offsets 9072 and 9080
(e.g. run 1: `0x00007fe870002ee0`, `0x00007fe870002ee4`); each equals
`base+0x2340` = user data of the string chunk at 9008. Chosen 0xDE bytes
replace both pointer values byte-for-byte.

This moves "pointer-bearing heap data is reachable by the write" from UNKNOWN
to OBSERVED and reproducible. It does NOT demonstrate grooming of a specific
target object, a chosen pointer value, or a controlled dereference of the
clobbered pointers: the write is sequential and overwrote whatever happened to
be adjacent in this unmodified allocation sequence, and the pointers' owning
object was not identified (allocation-site tracing would perturb the layout).
Post-auth `/auth` and the subsystem-supplied format table remain lab
conditions; no off-loopback probe.

## Chosen-pointer dereference in the live build (wake 13, 2026-11-21 04:36Z)

Wake 12 left the two pointers inside the chosen-byte write unidentified. A
full chunk dump (scratch-only, same five-patch pinned build, loopback `-auth`)
identifies the string at `out_buffer+9024` as
`"com\0freerdp\0channels\0rdpsnd\0server\0"` and the pointer array at
`out_buffer+9072` as its five component pointers plus NULL. That is exactly
`WLog_ParseName()` (`winpr/.../wlog.c:812-853`): a log tag strdup'd with dots
replaced by NULs and a `calloc(count+1, sizeof(LPSTR))` array. The 144-byte
`s_wLog` struct (`wlog.h:61-81`) sits at `out_buffer+8880`, with its `Names`
field at `+8904` — also inside the write. The pointer-bearing object is the log
object of `com.freerdp.channels.rdpsnd.server`, the channel performing the copy.

With a server-side `WLOG_FILTER='com.freerdp.server:TRACE'` (non-matching prefix
of ≥2 components) and a scratch-only `WLog_INFO(TAG, ...)` immediately after the
real `CopyMemory`, an ordinary post-write log call faults inside real FreeRDP
code: gdb shows `WLog_GetFilterLogLevel.part.0 -> WLog_GetLogLevel ->
WLog_IsLevelActive -> WLog_Print_dbg_tag -> rdpsnd_server_send_samples`, on
`mov (%rax,%r15,8),%rsi`. With uniform 0xDE audio bytes `rax` (loaded from
`log->Names` at `out_buffer+8904`) is `0xdededededededede`; with the eight source
bytes at offsets 8904..8911 set to 0x41, `rax` is `0x4141414141414141`. The
The dereference base is therefore exactly the chosen bytes. One negative is
preserved with a raw log: overwriting the `Names` *array* at 9072..9119 alone
does not move the fault, because the struct field holding `Names` is clobbered
first. A second, no-filter negative (post-copy log call returns without
dereferencing `Names`; only glibc corruption follows) is recorded in
`pointer_control_stock.txt` but has no raw log in `wake13/`.

Evidence: `lab/freerdp2shell-src/pointer_control_stock.txt`; raw gdb/server logs
in `verify-live-out/wake13/` (the mixed-array negative is logged there).
Conditions: the log trigger is scratch-injected (no natural post-write log call
on this TAG was observed before glibc aborted in the unmodified path); the
filter env var is required; chosen bytes come from
the lab's server-side synthetic playback event, not a remote client; the wLog
object was found after the fact, not groomed. No committed replay patch, digest
or `verify_live.sh` change; scratch sources restored and rebuilt. No
off-loopback probe; post-auth and subsystem-supplied format table unchanged.

## Natural post-write log trigger (wake 14, 2026-11-21 04:54Z)

Wake 13's chosen-pointer dereference used a scratch `WLog_INFO(TAG, ...)`
immediately after the corrupted `CopyMemory`. That scratch log call is no
longer needed: an unmodified client PDU and an unmodified server log call
reach the same clobbered `s_wLog`. With the same chosen bytes at
`out_buffer+8904` and a scratch client-side `Sleep(2500)` after the second
`SNDC_FORMATS` PDU, FreeRDP's own `rdpsnd_send_quality_mode_pdu()` sends
`SNDC_QUALITYMODE` after the synthetic playback. `WLOG_FILTER` set, the live
stock-allocator server (127.0.0.1:23222, `-auth`) faults at
`mov (%rax,%r15,8),%rsi` in `WLog_GetFilterLogLevel.part.0` with
`rax=0x4141414141414141`; the backtrace is
`WLog_GetFilterLogLevel -> WLog_GetLogLevel -> WLog_IsLevelActive ->
WLog_Print_dbg_tag -> rdpsnd_server_handle_messages -> rdpsnd_server_thread`.
No log call was injected into server code. Control on port 23223 without
`WLOG_FILTER`: same wrap, same client quality-mode PDU, no fault (raw log
preserved in `verify-live-out/wake14/`).

Evidence: `lab/freerdp2shell-src/natural_log_trigger_stock.txt` and raw logs
in `verify-live-out/wake14/`. Boundaries unchanged in substance: the client
delay is a scratch timing change, the chosen bytes still come from the lab's
server-side synthetic playback rather than a remote client, the object was
found after the fact rather than groomed, `WLOG_FILTER` is required, and the
session is post-auth with a subsystem-supplied format table on loopback.
Committed replay patches, digests and `verify_live.sh` were not changed;
scratch sources were restored and rebuilt. This also supplies the raw log for
the no-filter negative that wake 13 recorded without one (witness nit #567).

## Evidence boundary

Rungs 1/2/3 established; rung 4 PASS with lab-chosen bytes at chosen OOB
offsets **on real library bytes through the real SNDC_FORMATS parser, the real
`rdpsnd_server_handle_messages()` dispatcher, the real WTS virtual-channel
reader and the real shadow activation logic**, in-process; wake 8 additionally
demonstrates MCS/channel join, an ACTIVE RDP session, rdpsnd PDUs over the wire
and an ASan `heap-buffer-overflow` in the LIVE server process (chosen 0xDE at
offset 8820). Wake 9 repeats the live chosen-byte overwrite under the stock
glibc allocator (no sanitizer): 7564 OOB bytes at offsets 8820..16383, no
fault at the write, and glibc `double free or corruption (!prev)` on teardown.
The write is sequential and unbounded. Wake 12 measured the live stock heap
layout: a 64-byte chunk at `out_buffer+9056` holding two live heap pointers sits
fully inside the 16384-byte chosen-0xDE write, reproducibly across three
sessions, so pointer-bearing heap data in the write path is OBSERVED, not
UNKNOWN. Wake 13 identified that object as the wLog object of
`com.freerdp.channels.rdpsnd.server` and demonstrated a chosen pointer value
(`0x4141414141414141`) controlling the dereference base in
`WLog_GetFilterLogLevel` under a scratch-injected post-copy log call and a
configured `WLOG_FILTER`. Wake 14 reached the same fault with no server-side
log injection: FreeRDP's own `SNDC_QUALITYMODE` receive path logs on that TAG
after the write (scratch client-side timing delay needed). Grooming of a
chosen target object remains UNKNOWN.
In FFmpeg-off builds the stock shadow server's `Activated` callback selects
only PCM, so a format table offering a wrap-capable tag is required
(subsystem-supplied, demonstrated; or FFmpeg-enabled, UNVERIFIED here).
Network reachability, the default NLA gate (wake 7) and the no-auth gate
behavior are observed over real loopback TCP. No off-loopback probe. Default
posture is post-auth (PR:L, CVSS 8.8); the no-auth lab configuration used for
the live session is the 9.8 case.

Brief: `reports/frontier-freerdp2shell.md`; harness:
`lab/frontier/freerdp2shell/{rdpsnd_overflow.c,run.sh}`. A one-command live
replay now exists (`lab/freerdp2shell-src/verify_live.sh`, 17 PASS / 0 FAIL
warm, 18 PASS / 0 FAIL clean room). Independent witness acceptance is CLOSED:
W31 verdict #532 recorded ESTABLISHED with no corrections. Author evidence is
now independently accepted. Wake 12 observed pointer-bearing heap data inside
the written range in the live stock build
(`lab/freerdp2shell-src/heap_layout_stock.txt`); wake 13 identified its owner
and demonstrated a chosen-pointer-value dereference in that build
(`lab/freerdp2shell-src/pointer_control_stock.txt`); wake 14 replaced the
scratch log trigger with the real client/server quality-mode log exchange
(`lab/freerdp2shell-src/natural_log_trigger_stock.txt`). Grooming of a specific
target object and an FFmpeg-enabled build remain UNKNOWN.
