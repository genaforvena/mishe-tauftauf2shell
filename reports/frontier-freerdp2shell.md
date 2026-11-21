# Frontier brief — FreeRDP rdpsnd server `select_format()` integer-wraparound heap overwrite (Freerdp2Shell)

**Status: admitted 2026-11-20 ~19:32Z as the `freerdp2shell` target under
standing approval #6. The handoff below was written pre-admission and says
"UNSUBMITTED"; that line is retained as the original claim state, not the
current one. The operator re-ran the digests-pinned harness at 19:30Z:
`ALL CHECKS PASS`, rc 0, both digests matching. Current state (2026-11-21):
rungs 1-3 established and rung 4 PASS, including a live loopback RDP session
with the wrap and heap overwrite in the server process and a controlled
pointer dereference. Witness verdicts #532 and #602 are ESTABLISHED. The
authoritative, continuously updated account is
`reports/freerdp2shell-status.md`. The file-only reproduction and its pinned
digests below are retained unchanged from admission; the grade, work status
and open questions below were updated on 2026-11-21 to match that account.

## Verified ground truth (claim sources + this lab, 2026-11-20)

- **Advisory**: GHSA-3m9q-g533-rqjq, "FreeRDP rdpsnd server — heap buffer
  overflow via integer wraparound in `rdpsnd_server_select_format()` (bypass of
  CVE-2026-63117 fix)" (published 2026-10-05, reporter Kanishka De Silva /
  HEXERLAB). CWE-122 via CWE-190. CVSS 3.1 8.8 High post-auth
  (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`), 9.8 Critical in no-auth deployments.
- **CVE**: CVE-2026-114045 (NVD/OSV record, public 2026-10-21). The GHSA page
  still shows "No known CVE"; the CVE record and OSV both map it to this issue.
- **Claimed primitive**: two ordinary `SNDC_FORMATS` PDUs from an RDP client
  (a benign PCM format, then a `WAVE_FORMAT_DVI_ADPCM` format with
  `nBlockAlign=4, nChannels=2`) followed by any server audio playback event.
  The second format makes a `UINT64` block-size expression wrap to near
  `UINT64_MAX`, corrupting `out_frames`; the subsequent sample copy is an
  unbounded, sequential heap write of client-supplied bytes. Advisory claims a
  crash and RCE-class corruption, not a demonstrated shell.
- **Affected / fixed (claims)**: affected FreeRDP `master <= 8ec6d3923b8951e
  11cda8cbd2983494aeb60ce90` (2026-09-23) and stable `<= 3.32.0`; earlier 3.x
  (<= 3.16.0) also lack the `nChannels/nBlockAlign != 0` guards and expose extra
  divide-by-zero paths. Fixed `>= 3.32.1` (released 2026-09-28, tag `bf217a5`).
- **Lineage**: the fix for CVE-2026-63117 (commit `b7ca093`, 2026-07-16) added
  `nBlockAlign >= 4` (DVI) / `>= 8` (ADPCM) scalar floors and
  `WINPR_ASSERT(bs > 0)` after the exact-zero `nBlockAlign=8,nChannels=2`
  division-by-zero. This candidate is a distinct variant one unit below the
  codec-consistency threshold that passes every one of those guards.
- **Deployment condition (claim)**: the rdpsnd **server** channel is present in
  FreeRDP-based RDP servers that redirect audio to clients. Default posture is
  post-authentication (PR:L); no-auth RDP deployments reach the 9.8 ceiling.
  This is a network-facing native C RDP server component, not a language
  runtime.
- **Claim sources read (external claims, not lab findings)**: GitHub GHSA,
  CVE record / OSV, NVD, FreeRDP 3.32.1 release page and ChangeLog, and raw
  `channels/rdpsnd/server/rdpsnd_main.c` at tags 3.32.0 and 3.32.1. Read-only
  provisioning only; no external probe.

## Source-bound mechanism (read from the 3.32.0 → 3.32.1 diff, not inferred)
*(All `rdpsnd_main.c` line numbers below are raw-file lines at the named tag,
from provisioning the raw source. The reader that produced an earlier draft
prepended six header lines, so its displayed numbers were +6; they are
corrected here.)*

At parse time, `rdpsnd_server_recv_formats()` (`rdpsnd_main.c:252-259`, 3.32.0)
rejects `nChannels == 0` / `nBlockAlign == 0` and applies only a scalar floor
per codec: DVI_ADPCM needs `nBlockAlign >= 4`. It never checks the codec's
consistency relation `nBlockAlign >= 4 * nChannels`. A client therefore places
`nBlockAlign=4, nChannels=2` in an `SNDC_FORMATS` record and passes.

`rdpsnd_server_select_format()` (3.32.0, lines 409-418):

```c
case WAVE_FORMAT_DVI_ADPCM:
    WINPR_ASSERT(format->nBlockAlign >= 4);   /* 4 >= 4  -> passes */
    WINPR_ASSERT(format->nChannels > 0);      /* 2 > 0   -> passes */
    const UINT64 bs = 4ULL * (format->nBlockAlign - 4ULL * format->nChannels);
    /* 4ULL*2 = 8; 4-8 = 0xFFFFFFFFFFFFFFFC; *4 = 0xFFFFFFFFFFFFFFF0 */
    WINPR_ASSERT(bs > 0);                     /* huge > 0 -> passes */
    context->priv->out_frames -= context->priv->out_frames % bs;  /* 2205 -> 0 */
    if (context->priv->out_frames < bs)
        context->priv->out_frames = bs;       /* = 0xFFFFFFFFFFFFFFF0 */
```

`out_frames` is committed at line 400 and mutated here **before** any
allocation. Line 440 computes `out_buffer_size = out_frames *
src_bytes_per_frame` = `0xFFFFFFFFFFFFFFF0 * 4` = `0xFFFFFFFFFFFFFFC0`. The
`realloc` at line 444 fails for that size; lines 446-451 return
`CHANNEL_RC_NO_MEMORY` but **do not roll `out_frames` back**. Integrators
(`shadow_rdpsnd.c`, `mf_rdpsnd.c`, `wf_rdpsnd.c`) log a warning and continue.

The sink, `rdpsnd_server_send_samples()` (3.32.0, lines 765-785):

```c
while (nframes > 0) {
    const size_t cframes = MIN(nframes, out_frames - out_pending_frames);
    size_t cframesize = cframes * src_bytes_per_frame;   /* 4096*4 = 16384 */
    CopyMemory(out_buffer + out_pending_frames*src_bytes_per_frame, buf, cframesize);
    buf += cframesize; nframes -= cframes; out_pending_frames += cframes;
}
```

Because `out_frames` is now near `UINT64_MAX`, `out_pending_frames` never
reaches it, the PDU is never flushed, and every call appends at a monotonically
advancing offset — an unbounded sequential heap overwrite, not a single
bounded overflow. The copied `buf` bytes and the copy stride come from the
server's own audio-capture source (`src_format->wBitsPerSample/8 * nChannels`),
not from the client: wake 17 traced this in pinned 3.32.0
(`rdpsnd_main.c:383-385,770-773`; `src_format` is set from the server's own
formats). The client chooses the wrap-triggering format record and, via the
`SNDC_FORMATS` record count, the offset of an adjacent heap object (wake 18);
it does NOT choose the bytes written in a stock build. The lab's chosen-byte
rung-4 calls use synthetic playback as a stand-in for server capture.

The real 3.32.1 fix replaces the assertions with an overflow-safe division
guard (`rdpsnd_main.c:409-412`):

```c
if (format->nBlockAlign / 4ull < format->nChannels) goto out;  /* 4/4=1 < 2 -> reject */
if (format->nChannels == 0) goto out;
```

and the analogous `/ 7` guard for ADPCM (`:429-432`). Note the upstream fix
does **not** adopt the advisory's "commit state only after allocation succeeds"
layer; with the guard in place the hostile size is simply unreachable.

## Local reproduction (file-only harness, 2026-11-20)

`lab/frontier/freerdp2shell/`: `rdpsnd_overflow.c` transcribes the two functions
above (AUDIO_FORMAT fields, `out_frames` formula, `src_bytes_per_frame = 4`,
realloc-failure-without-rollback, copy loop); `BUILD_FIXED` applies the exact
3.32.1 division guard. No sockets, no FreeRDP library, no network. `run.sh`
builds `vuln`, `fixed` and `asan` variants and prints `ALL CHECKS PASS`, rc 0,
twice consecutively. Pinned digests:

```
d0a314876577d6a7dcb26485df2e414b29e7f85aab32b6bc5e5865be3474d08e  rdpsnd_overflow.c
c5186500d60c173ba948f6b0a8633927d0c57749014d52e5f2ecf79fd8e9c5c8  run.sh
```

- **Rung 1 (reproducible trigger + state failure)**:
  `rc2=2 out_frames=0xfffffffffffffff0 realloc_failed=1`,
  `oob_writes=7564 first_oob=8820 last_oob=16383 copy_base_alloc=8820`.
  The 8820-byte allocation (2205 frames × 4) is the same one in the advisory's
  reporter PoC.
- **Rung 2 (chosen bytes at chosen offsets)**: client bytes `ab` and `cd`
  placed at source indices 8820 and 12000 land verbatim at OOB heap offsets
  8820 and 12000.
- **Rung 3 (ASan-confirmed corruption)**: `heap-buffer-overflow`,
  `WRITE of size 16384`, `0 bytes after an 8820-byte region`, from `memcpy` in
  `do_copy` via `send_samples`; allocation from `realloc` in `select_format`;
  process rc 1. Matches the advisory's own reporter ASan signature.
- **Rung 4 (chosen bytes, unbounded sequential write)**: call 1 writes chosen
  byte `de` at OOB offset 8820; call 2 writes chosen byte `ad` at OOB offset
  21384; `out_pending_frames=8192` and never approaches `out_frames`, showing
  the write advancing monotonically with client data.
- **Controls**: benign PCM leaves `oob_writes=0`; the 3.32.1-guard build rejects
  with `rc2=1 out_frames=2205 realloc_failed=0 oob_writes=0`; five vulnerable
  rung-1 traces byte-identical.

Grade at admission: rungs 1/2/3 established, rung 4 PASS in the extracted
harness with lab-chosen bytes at lab-chosen offsets. Current grade, after
wakes 3-18: rung 4 PASS on real library bytes through the real `SNDC_FORMATS`
parser, dispatcher, WTS reader and shadow activation logic, plus a live
127.0.0.1 server session with an ASan `WRITE of size 16384` at offset 8820 and
a stock-allocator 7564-byte chosen-value overwrite. Heap layout, a
pointer-bearing target object, its client-controlled offset and a
chosen-pointer dereference are OBSERVED in that live build; the written bytes
are lab-supplied, the format table is subsystem-supplied, the dereference
needs a client-side delay and `WLOG_FILTER`, and the default posture is
post-auth (PR:L). Full evidence and boundaries:
`reports/freerdp2shell-status.md`; witness verdicts #532 and #602 ESTABLISHED
with no corrections.

## Rung-4 feasibility assessment (at admission; see current grade above)

Tractability **HIGH**. Public fix diff, small single-subsystem change, no
hardware gate, and a full bulk `memcpy` rather than a byte-at-a-time consumer:
the deterministic chosen-value write does not depend on glibc `memcpy`
tail-first/store-first partial-overwrite windows (the caveat that killed rung
4 through other memcpy consumers). At admission, byte identity was assumed
because `buf` was read as client audio data; wake 17 corrected that: in the
pinned 3.32.0 source the bytes and stride come from the server's own capture,
so remote byte choice is NOT established and every "chosen bytes" rung-4 claim
is explicitly lab-synthetic. Pointer control and object placement were also
open then; wakes 12-14 and 18 observed a chosen-pointer-value dereference in
the identified wLog object and client-controlled placement of that object by
32 bytes per extra format record.

Reachability caveat that must stay prominent: default posture is
post-authentication (PR:L); only no-auth RDP deployments reach 9.8. The live
loopback evidence uses a no-auth server and a subsystem-supplied wrap-capable
format table; neither the default format list nor a production deployment was
shown to reach the sink.

## Work completed after admission (was "Cheapest next step")

The admission plan was executed and exceeded: source-built 3.32.0 with server
channels under ASan and a plain build, the advisory PoC against the real
library (wakes 3-6), a real loopback shadow server for transport and the auth
gate (wake 7), a full MCS/attach/channel-join RDP session with PDUs on the wire
and a live ASan `WRITE of size 16384` (wake 8), a stock-allocator chosen-byte
overwrite (wake 9), a one-command witness replay (wake 10, independently
accepted W31 #532), stock heap layout and pointer control (wakes 12-14), the
FFmpeg format gate (wake 16, witness #602), the real-audio-source trace
(wake 17) and client-controlled grooming (wake 18). Commands and digests are
in `docs/reproducibility.md` and `reports/freerdp2shell-status.md`. No
external system was probed; all servers bound 127.0.0.1 only.

## What remains open

- A primary source or live trace showing the copied bytes and stride are
  influenced by the remote client would turn the lab-chosen-byte rung 4 into
  remote byte control. Wake 17's source reading is NEGATIVE for that in the
  pinned 3.32.0 tree; deployment-specific audio capture stays UNKNOWN and is
  not measurable in this lab.
- A stock-format-list route to a wrap-capable tag would remove the
  subsystem-supplied-table condition. Wake 6 measured the FFmpeg-off list as
  PCM only and wake 16 measured an experimental FFmpeg build exposing tag 2;
  neither is a stock deployment.
- A post-write dereference without the scratch client delay would strengthen
  the pointer-control claim. Wake 14 observed the real quality-mode log path
  but needed the delay; wake 15 recorded the unaided NEGATIVE.
- Default-posture (post-auth, PR:L) live impact over a non-loopback RDP client
  is not claimed; only the loopback session and the no-auth gate behavior were
  observed.
- The admission-status note above supersedes the pre-admission handoff
  questions; nothing here creates a target mind or window.
