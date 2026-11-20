# Frontier brief — FreeRDP rdpsnd server `select_format()` integer-wraparound heap overwrite (Freerdp2Shell)

**Status: UNSUBMITTED frontier candidate, 2026-11-20. Not admitted, no target
mind or window yet. Scouting, rungs 1–3 established locally; rung 4 established
in the extracted harness only.**

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

At parse time, `rdpsnd_server_recv_formats()` (`rdpsnd_main.c:258-265`, 3.32.0)
rejects `nChannels == 0` / `nBlockAlign == 0` and applies only a scalar floor
per codec: DVI_ADPCM needs `nBlockAlign >= 4`. It never checks the codec's
consistency relation `nBlockAlign >= 4 * nChannels`. A client therefore places
`nBlockAlign=4, nChannels=2` in an `SNDC_FORMATS` record and passes.

`rdpsnd_server_select_format()` (3.32.0, lines 415-423):

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

`out_frames` is committed at line 406 and mutated here **before** any
allocation. Line 446 computes `out_buffer_size = out_frames *
src_bytes_per_frame` = `0xFFFFFFFFFFFFFFF0 * 4` = `0xFFFFFFFFFFFFFFC0`. The
`realloc` at line 450 fails for that size; line 452-457 returns
`CHANNEL_RC_NO_MEMORY` but **does not roll `out_frames` back**. Integrators
(`shadow_rdpsnd.c`, `mf_rdpsnd.c`, `wf_rdpsnd.c`) log a warning and continue.

The sink, `rdpsnd_server_send_samples()` (3.32.0, lines 771-781):

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
advancing offset with **client-chosen `buf` bytes** — an unbounded sequential
heap overwrite, not a single bounded overflow. The `buf` argument is the audio
sample data supplied by the client/audio source, so both the bytes and (via the
number of frames sent before a call) the destination offset are attacker
influenced.

The real 3.32.1 fix replaces the assertions with an overflow-safe division
guard (`rdpsnd_main.c:415-418`):

```c
if (format->nBlockAlign / 4ull < format->nChannels) goto out;  /* 4/4=1 < 2 -> reject */
if (format->nChannels == 0) goto out;
```

and the analogous `/ 7` guard for ADPCM (`:435-438`). Note the upstream fix
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

Grade: rungs 1/2/3 established, rung 4 **PASS in the extracted harness with
client-chosen bytes at client-chosen offsets**. Live FreeRDP process, the real
`SNDC_FORMATS` PDU parse path, an RDP session, the allocator's real heap layout,
network reachability and the auth gate stay UNKNOWN.

## Rung-4 feasibility assessment

Tractability **HIGH**. Public fix diff, small single-file subsystem, no hardware
gate, no need to guess the copied bytes: `buf` is client audio data and the copy
is a full bulk `memcpy`, so "chosen bytes at chosen offsets" holds directly
without depending on glibc `memcpy` tail-first/store-first partial-overwrite
windows (the caveat that killed rung 4 through other memcpy consumers). Pointer
control in the real channel layout is a separate, harder question — the write
is sequential so reaching a specific heap object needs grooming, and no
convenient adjacent pointer-sized field is obvious from the source alone.

Reachability caveat that must stay prominent: default posture is
post-authentication (PR:L); only no-auth RDP deployments reach 9.8. Even so,
the primitive is stronger and more directly attacker-controlled than the
opt-in-gate FreeSWITCH lane.

## Cheapest next step

Build FreeRDP 3.32.0 with `-DWITH_SERVER=ON -DWITH_CHANNELS=ON
-DBUILD_TESTING=OFF -DWITH_CLIENT=OFF` under ASan/UBSan, compile the advisory's
`PocRdpsndOverflow.c` against the built libs, and run it with
`ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1` to move from the
extracted harness to the real library (still file-only). Then feed the same two
`SNDC_FORMATS` PDUs into a loopback-only (127.0.0.1) FreeRDP `shadow` server to
move PDU-parse reachability and the auth gate from UNKNOWN to evidence. No
external system is probed.

## What would change this assessment

- A fixed 3.32.1 build still producing the overflow, or a primary source
  showing the sample buffer is not client-controlled, breaks the differential.
- A live build closing the channel before `SendSamples` would reduce the
  network claim to UNKNOWN while leaving the extracted result intact.
- A chosen function-pointer target in the real channel heap layout would
  promote rung 4 from chosen-bytes to pointer control.
- Admission is the operator's call; this brief does not create a target mind or
  window. Nothing here duplicates an existing lane.
