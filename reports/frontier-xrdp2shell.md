# Frontier brief — xrdp virtual-channel-to-chansrv fixed-buffer heap overflow (Xrdp2Shell)

**Status: frontier candidate, 2026-11-20. Rungs 1–3 established locally,
rung 4 PASS in the extracted harness only. Live process, PDU path and auth
gate UNKNOWN. Two handoff artifacts exist: this brief and live two-pane
window 19 (`xrdp2shell`, inner socket); site admission remains the
operator's call.**

## Verified ground truth (claim sources + this lab, 2026-11-20)

- **Advisory**: GHSA-hh7r-2rmq-q4g4, "Heap-based Buffer Overflow in xrdp
  Virtual Channel Forwarding" (neutrinolabs/xrdp, published 2026-07-02). High
  8.8, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-122. Discovered by
  Atuin / Tianchu Chen (Tencent Xuanwu Lab).
- **CVE**: CVE-2026-44178, "xrdp: Channel Data Forwarding Fixed-Size Buffer
  Overflow" (CNA GitHub, published 2026-07-20). Affected `< 0.10.6.1`;
  fixed in `0.10.6.1` (released 2026-07-07, tag `v0.10.6.1`, one of ten
  security fixes in that release).
- **Claimed primitive**: an authenticated RDP client sends a crafted virtual
  channel message that exceeds a fixed-size xrdp→chansrv buffer; heap
  corruption, DoS or code execution with xrdp privileges is claimed. No
  shell is demonstrated by the advisory.
- **Claim sources read (external claims, not lab findings)**: GHSA page, CVE
  record, v0.10.6.1 release notes, GitHub `compare/v0.10.6...v0.10.6.1`,
  fix commit `43dc9c3b71e5e46733d70ec0239c482ee264cd9f`, and raw source at
  both tags. Read-only provisioning only; **no external probe, no traffic to
  any non-loopback address**.
- **Deployment condition (claim)**: network-facing RDP server component,
  post-authentication (PR:L); the dynamic virtual channel must be open.
  No default-on unauthenticated path is claimed.

## Source-bound mechanism (read from the fix, not inferred)

Fix commit `43dc9c3b71e5e46733d70ec0239c482ee264cd9f` ("CVE-2026-44178:
Heap overflow in xrdp->chansrv msgs", cherry-picked from
`679faa64bc05a3959fcac888f36a768fad7dcce1`) changes only
`xrdp/xrdp_mm.c`. Raw-file lines below are from the exact provisioned tags
(digest `d743c53f0f2f85e2cd0abc861996887c248a8270ebc9d75697f7208dd63d10d2`
for v0.10.6 and `4b6c64e865dc4c1998a6a77911e2a0c8f9cfa9cd0d9570992797971a41e78370`
for v0.10.6.1); no reader-added header lines are included.

In v0.10.6, all three xrdp→chansrv writers ask for a fixed 8192-byte stream:

- `xrdp_mm_drdynvc_data_first()` (`xrdp_mm.c:2318-2346`) calls
  `trans_get_out_s(trans, 8192)` at :2330, writes a 28-byte header
  (:2335-2342) and then `out_uint8a(s, data, bytes)` at :2343.
- `xrdp_mm_drdynvc_data()` (`:2351-2377`) does the same with a 24-byte
  header (:2367-2373) and the copy at :2374.
- `xrdp_mm_process_channel_data()` (`:2763-2809`) uses a 26-byte header
  (:2794-2801) and `out_uint8a(s, data, length)` at :2802.

The stream is genuinely 8192 bytes: `chan_trans` is created with
`trans_create(TRANS_MODE_UNIX, 8192, 8192)` at `xrdp_mm.c:3135`;
`trans_get_out_s()` (`common/trans.c:1026-1041`) calls
`init_stream(out_s, size)`, which keeps the existing buffer unless the
requested size is larger (`common/parse.h:248-259`). `out_uint8a` expands to
`out_uint8p`, a plain `g_memcpy` with only a `USE_DEVEL_STREAMCHECK`-gated
bounds check (`common/parse.h:563-572`, `:82-90`) — absent in an ordinary
build. Each copy therefore writes past 8192 once header + payload exceeds it
(8164 / 8168 / 8166 bytes respectively).

The client controls the length. `drdynvc_process_data_first()`
(`libxrdp/xrdp_channel.c:425-498`) parses a 1/2/4-byte `total_bytes`
(:441-465), computes `bytes = s->end - s->p` (:466) and checks only
`total_bytes >= 1590 && bytes <= total_bytes` (:472) before invoking
`data_first(..., bytes, total_bytes)` (:490-491). The DYNVC reassembly path
`xrdp_channel_process_drdynvc()` (`:547-658`) allocates its staging stream to
the client-supplied `total_length` (:586) and appends each virtual-channel
chunk (:569-613), so a multi-chunk reassembled message can make `bytes`
arbitrarily large; no ceiling near 8192 exists in this source. The static
channel path passes `size = s->end - s->p` into the callback
(`xrdp_channel.c:164-196`), reaching `process_channel_data()` with the same
fixed-size stream.

The 0.10.6.1 fix replaces every `trans_get_out_s(trans, 8192)` with
`trans_get_out_s(trans, pdu_size)` computed from the actual header + payload,
rewrites the two length fields from that value, and adds
`if (length > 65535) return 1;` plus a hard reject when
`total_length < length` in `process_channel_data()`. With exact allocation
the hostile size can no longer overflow the buffer. The advisory's
"fixed-size buffer without bounds checking" claim is therefore source-bound.

## Local reproduction (file-only harness, 2026-11-20)

`lab/frontier/xrdp2shell/xrdp_overflow.c` transcribes the three writers,
`trans_get_out_s`/`init_stream`/`out_uint8p` and the 8192-byte `chan_trans`.
`run.sh` builds a non-ASan instrumented variant and an ASan variant with a
real exact 8192-byte allocation, then checks every leg. No sockets, no xrdp
library, no network. Pinned digests:

```
46735a43423f8dbd609db4d90a744f0c797fea79f50d64357015cad8a10eee04  xrdp_overflow.c
2da4d3ea48f77431f7edea978bed63e4a7e5d9271a929a6a4c24534ee842e73f  run.sh
```

`bash lab/frontier/xrdp2shell/run.sh` printed `ALL CHECKS PASS`, rc 0, on two
consecutive runs:

- **Rung 1 (reproducible trigger + state failure)**: 28-byte header plus
  20000 client bytes gives `oob_writes=11836 first_oob=8192 last_oob=20027`.
  The static path with its 26-byte header gives `oob_writes=11834
  first_oob=8192 last_oob=20025`.
- **Rung 2 (chosen bytes at chosen offsets)**: client bytes `ab` and `cd`
  land verbatim at OOB stream offsets 8228 and 12028.
- **Rung 3 (ASan-confirmed corruption)**: `heap-buffer-overflow`,
  `WRITE of size 20000`, `0 bytes after an 8192-byte region`, from `memcpy`
  in `do_copy` via `drdynvc_data_first`, allocation in `init_trans`;
  process rc 1.
- **Rung 4 (chosen bytes across two messages)**: a data-first message places
  `de` at OOB offset 8228, a subsequent data message places `ad` at OOB
  offset 12024; no sink special-case for the instrumentation bytes.
- **Controls**: the 0.10.6.1 exact-size allocation gives
  `data_first_oob=0 data_oob=0 channel_rc=0 channel_oob=0`; a benign
  100-byte payload gives `oob_writes=0`; five vulnerable rung-1 traces are
  byte-identical.

Grade: rungs 1/2/3 established, rung 4 **PASS in the extracted harness with
client-chosen bytes at client-chosen offsets**. Live xrdp process, real
DRDYNVC PDU parse and reassembly path, dynamic-channel open, stock allocator
layout, network reachability and the authentication gate remain UNKNOWN.
The harness deliberately leaks the corrupted buffers at exit: freeing them
corrupts allocator metadata, and no graded observation depends on the free.

- **Rung 1 (reproducible trigger + overflow)**: 28-byte header plus

Tractability **HIGH for chosen bytes, UNKNOWN for pointer control**. Public
fix diff, single-file subsystem, no hardware gate, no need to guess the
copied bytes: the sink is one bulk `memcpy` of client payload, so
"chosen bytes at chosen offsets" holds directly without relying on
`memcpy` tail-first/store-first partial-overwrite windows. The whole 11.8 KB
span is attacker-chosen contiguous data. Pointer control or control-flow
hijack is a separate question: reaching a useful heap object needs grooming,
and no convenient adjacent pointer-sized field is obvious from this source.

Reachability caveats that must stay prominent: authentication is required
(PR:L), a dynamic channel must be open, and a real session needs xrdp, sesman
and a channel server over loopback. Only on an unauthenticated deployment
would the 9.8 ceiling apply; nothing here claims that posture.

## Cheapest next step

Build xrdp 0.10.6 with `-fsanitize=address` under `lab/`, start xrdp+sesman+
chansrv bound strictly to 127.0.0.1 with a local X backend, connect with a
local RDP client, open a dynamic channel, and send a reassembled
`DYNVC_DATA_FIRST` carrying >8164 bytes with a recognizable marker. An ASan
trace at `xrdp_mm_drdynvc_data_first()` would move PDU-parse reachability and
the auth gate from UNKNOWN to evidence. No external system is contacted.

## What would change this assessment

- A primary source capping reassembled DYNVC payloads at ≤8164 bytes, or a
  stock build with `USE_DEVEL_STREAMCHECK` enabled, would break the premise.
- A live build that closes the channel before the chansrv forwarding call
  would reduce the network claim to UNKNOWN while leaving the extracted
  result intact.
- A chosen pointer/heaped object in the real chansrv transport layout would
  promote rung 4 from chosen bytes to pointer control.
- Site admission, charter and wake trigger units remain the operator's and
  the person's call; the target window already exists. This brief does not
  duplicate an existing lane.
