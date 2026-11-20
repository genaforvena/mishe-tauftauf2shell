# Frontier brief — FreeSWITCH mod_xml_rpc WebSocket extended-length heap over-write (Freeswitch2Shell)

**Status: admitted 2026-11-20 ~17:52Z under standing approval #6; operator
reconciliation 18:28Z and frontier's clean re-run 19:02Z below.** Frontier was
cut mid-wake before it pinned harness numbers; both reproduction sections are
at the end of this file. The `freeswitch2shell` charter, docs/task.md entry and
committed brief/status exist; wake trigger units remain the person's full-flag
sync. The two-pane window and restorer registry entry are live.

## Verified ground truth (claim sources + this lab, 2026-11-20)

- **Advisory**: CVE-2026-116785 / GHSA-jj89-q47c-gh94, "FreeSWITCH:
  Pre-authentication heap out-of-bounds write in mod_xml_rpc WebSocket frame
  length handling" (GHSA published 2026-10-28, CVE record 2026-11-05, CNA
  GitHub, Inc.). CWE-122 / CWE-681 / CWE-787. CVSS 3.1 9.1,
  `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`. Credit: Tristan Madani, Talence
  Security.
- **Claimed primitive**: a client that completes a WebSocket upgrade on an
  enabled `mod_xml_rpc` endpoint reaches `ws_read_frame()` before HTTP digest
  authentication. A frame using the 8-byte extended length field with a value
  whose surviving low word is negative bypasses the signed buffer-size check
  and is reinterpreted as an enormous unsigned count; client-supplied bytes
  then overwrite memory past the 64 KiB receive buffer, through the adjacent
  send buffer and into the connection handle's own state (buffer length,
  payload pointer, `SSL *`). The advisory claims a crash and pointer-state
  corruption, explicitly **not** demonstrated RCE.
- **Affected / fixed (claims)**: affected `<= 1.11.1` (all current 1.10 and
  1.11 releases); fixed `>= 1.11.2`. Upstream fix
  `d557ca6d29e6da4f10824dc158100906a592b91a` ("Merge commit from fork"),
  vulnerable parent `fbac12b451a1`. One file changed,
  `src/mod/xml_int/mod_xml_rpc/ws.c`, +36/−7.
- **Deployment condition (claim)**: `mod_xml_rpc` must be loaded and its
  `enable-websocket` set; both are opt-in and absent from the stock
  `modules.conf.xml` / `xml_rpc.conf.xml`. Where enabled, the endpoint listens
  on the module's `http-port` (8080 by default). `/socket` is dispatched to the
  WebSocket handler ahead of `auth-realm` checks, so setting HTTP auth does not
  close the path.
- **Distinct from earlier FreeSWITCH screens**: CVE-2026-116570 /
  GHSA-294g-hq4w-c275 was screened out because the overflow bytes are the
  *configured* credential's base64 tail, not sender-chosen; GHSA-f73w-xph4-pjp3
  was declined as SIP-facing. This candidate is in the HTTP/WebSocket module
  and the copied bytes are chosen by the unauthenticated sender.
- **Claim sources read (external claims, not lab findings)**: GitHub GHSA,
  CVE record, Casco CVE mirror, upstream fix commit and diff, and raw
  `ws.c`/`ws.h` at the vulnerable parent. No exploit page, no external probe.

## Source-bound mechanism (read from the pinned vulnerable parent, not inferred)

All `ws.c` line numbers below are absolute lines in the byte at
`fbac12b451a1` (sha256 `5a07965f530296bec3840c6c8a7a29c00f34d87f76e34eacf44978ef01d84d3b`).

`ws.h` defines `typedef int issize_t;` and the heap-allocated handle:

```c
typedef struct wsh_s {
    ws_tsession_t *tsession;
    char buffer[65536];
    char wbuffer[65536];
    size_t buflen;
    issize_t datalen;
    issize_t wdatalen;
    char *payload;
    issize_t plen;
    issize_t rplen;
    SSL *ssl;
    int handshake;
    uint8_t down;
    int secure;
    uint8_t close_sock;
} wsh_t;
```

`ws_init()` (`ws.c:334-345`) `malloc`s `wsh_t`, zeroes it and sets
`wsh->buflen = sizeof(wsh->buffer)` = 65536.

`ws_read_frame()` (`ws.c:387-544`) reads 14 bytes into `wsh->buffer` and, for
length code `127` (`ws.c:449-463`), takes the eight length bytes at
`wsh->payload` (`= &buffer[2]`) as a `uint64_t *`, advances `payload` by eight
(to `&buffer[10]`) and assigns:

```c
wsh->plen = ntohl((u_long)*u64);   /* 32-bit swap; plen is signed int */
```

On little-endian x86-64 `ntohl` swaps only the low 32 bits of the native
`uint64_t`, which are formed from the **first four frame bytes**. Sending
`FF FF FF FF` there makes the swapped word `0xFFFFFFFF`, which narrows to
`plen = -1`. The two consequences are kept separate:

1. **Signed guard is bypassed.** `need = plen - (datalen - need)` becomes
   `-1 - (14 - 10) = -5`. The guard at `ws.c:489`,
   `(need + wsh->datalen) >= (issize_t)wsh->buflen`, evaluates `9 >= 65536`
   and passes. `wsh->rplen = plen - need = 4`.
2. **The copy is unbounded.** The loop at `ws.c:497-509`
   calls `ws_raw_read(wsh, wsh->payload + wsh->rplen, need)`. Its third
   parameter is `size_t`, so the negative `need` becomes a huge unsigned count;
   `need -= r` only makes it more negative, so the loop runs until the input is
   exhausted (`r < 1`). Every byte after the 14-byte header is copied from
   `&buffer[14]` onward with no bound check, and the trailing NUL at
   `ws.c:527` lands at `payload + rplen`. In the extracted harness the source
   side is pre-filled, so every copied byte is sender-chosen; see the
   real-source section below for the boundary on that claim.

The 64 KiB `buffer` and 64 KiB `wbuffer` are followed in the same allocation
by `buflen`, `datalen`, `wdatalen`, `payload`, `plen`, `rplen` and `ssl`.
`offsetof(wsh_t, ssl)` is 131112 on this host, so roughly 131098 payload bytes
place a chosen 8-byte value in `wsh->ssl`; `ws_raw_write()` (`ws.c:315-332`)
and `ws_destroy()` (`ws.c:347-373`) dereference that pointer. In the extracted
harness this is a materially stronger primitive than the hands-off corruption
claimed in the advisory: chosen bytes at chosen offsets, including
pointer-sized fields. The real-source boundary is below; the opt-in
configuration gate remains a separate condition on any impact claim.

The fix decodes all eight bytes with `ws_get_be64()` into `uint64_t plen64`,
rejects `plen64 >= wsh->buflen` with `WS_DATA_TOO_BIG` **before** narrowing to
the signed field, and emits the extended length with a matching
`ws_put_be64()` in `ws_write_frame()`. Frames that previously parsed are
unaffected.

## Rung ladder and feasibility

Tractability **HIGH**: public fix diff, small single-file subsystem, no
hardware gate, no need to guess the written bytes. Standalone extracted
functions give rungs 1–3; an 8-byte chosen value at a known `offsetof(wsh_t,
ssl)` gives pointer control in the harness. The honest boundary is that
`TSession`/`ConnRead` are replaced by a local input buffer, and a live
FreeSWITCH process, the WebSocket upgrade path, the real heap layout and the
reachability claim stay UNKNOWN until a loopback-only `mod_xml_rpc` build is
driven. The configuration gate (module and `enable-websocket` off by default)
is real and must stay prominent in any impact claim.

## Cheapest next step

Run the committed differential (`lab/frontier/freeswitch2shell/run.sh`), then
build a loopback-only FreeSWITCH 1.11.1 with `mod_xml_rpc` and
`enable-websocket` enabled and drive a single `/socket` upgrade plus one
extended-length frame on 127.0.0.1. That would move the network claim from
UNKNOWN to evidence and show the real offset to `wsh->ssl` under the stock
allocator.

## What would change this assessment

- A primary source showing the copied bytes are not sender-chosen, or a fixed
  build that still accepts the frame, breaks the differential.
- A default-on, unauthenticated web-facing endpoint would outrank the
  opt-in `mod_xml_rpc` gate.
- In a live build, an early protocol close before the copy would reduce the
  network claim to UNKNOWN while leaving the extracted-function result intact.

## Operator reproduction, 2026-11-20 18:28Z

Frontier was cut mid-handoff: the recorded `logs/digests.txt` named a
`ws_overflow.c` digest (`f26f2df4…`) that did not match the on-disk source,
and `logs/summary.log` ended `CHECKS FAILED`. I copied the current
`ws_overflow.c` and `run.sh` into a throwaway directory and ran `bash run.sh`
there; all three variants rebuilt and produced the following. The original
logs remain untouched for comparison.

- Pinned digests of the sources actually run: `ws_overflow.c`
  `7eeb5d262ec86b14174641e82f58d8c8bda52fa8d893205991b850e0406d3c6a`,
  `run.sh` `089d7e337e91c0c9dd004dc18ed5ba1b0cc45ef927063310088e4fe44d918104`.
- Rung 1: `plen=-1 need=-5 datalen=14 rplen=4 guard_passed=1`, 2928 OOB
  writes, `first_oob=65536`, `last_oob=66999`. The C harness prints an
  internal `RESULT=FAIL` because its hard-coded expected count (1464) and
  `first_raw_requested` value are stale after the source edit; the guard
  bypass and OOB write themselves are observed.
- Rung 2: chosen bytes reach `wbuffer[0..3]` and `wbuffer[1024..1027]` in two
  distinct patterns (A `dedfe0e1`/`cacbcccd`, B `11121314`/`55565758`); the C
  harness marks both `RESULT=PASS`. `run.sh` still greps older literals
  (`deadbeef`/`cafebabe`, `11223344`/`55667788`) and treats the WebSocket
  close code `-1002` as a nonzero-exit failure, so the driver marks it FAIL.
- Rung 3: ASan reports `heap-buffer-overflow`, `WRITE of size 132146`, in
  `memcpy` called from `ws_raw_read` (`ws_overflow.c:197`) via
  `ws_read_frame` (`:415`), starting 0 bytes past the 131136-byte `wsh_t`
  allocation. Confirmed memory corruption.
- Rung 4: chosen 8-byte value at `offsetof(wsh_t, ssl)=131112`
  (`before=(nil) after=0x58e18f53e6f1`), `marker_called=1`, `rc=42`. Chosen
  pointer control and marker execution are observed in the extracted harness,
  not in a live process.
- Controls: an ordinary 8-byte frame leaves canaries unchanged with zero OOB
  writes; untouched `ssl` leaves the marker uncalled; the fixed build rejects
  with `rc=-1009`, `oob_writes=0`; five repeat vulnerable runs are
  byte-identical.

At that time the driver printed `CHECKS FAILED` only because of stale
exit-code and literal-pattern expectations, not because a security observation
regressed. Those expectations and two genuine accounting/exit-code defects in
the C harness were repaired at 19:02Z; the next section supersedes this one for
current numbers. No live FreeSWITCH process, WebSocket upgrade or loopback
network path was tested by this reproduction.

## Frontier re-run and harness repair, 2026-11-20 19:02Z

Re-ran `bash lab/frontier/freeswitch2shell/run.sh` from clean HEAD. It now
prints `ALL CHECKS PASS` with driver rc 0, twice in a row. Pinned source
digests for this run (replacing the 18:28Z pins in the operator section above,
which remain a truthful record of what that run executed):

```
75433b5dcc26a4a445bd6191c5c7f345d090810d8554d3d866062c7d359075e0  ws_overflow.c
637cfa361ca1fe491c455b5595adf6880b01249300f67ac2c470469e7cfa5965  run.sh
```

The repair was not cosmetic. Instrumenting a throwaway copy in `/tmp/fs-debug`
showed two harness defects that inflated or inverted the recorded evidence:

1. `trace_copy()` (ws_overflow.c:115-133) computed `out = 0 - (size_t)(end - d)`
   for the third `ws_raw_read()` call, which requests zero bytes at an offset
   past the buffer. That `size_t` underflow added 1464 phantom writes, so the
   operator's `oob_writes=2928` was exactly double the real extent. Adding an
   `n == 0` guard fixed it. Observed trace before the fix:
   `dest_off=0 n=14`, `dest_off=14 n=66986`, `dest_off=67000 n=0 oob_before=1464`
   -> final `2928`. The overwritten byte range `65536..66999` (1464 bytes) was
   always real; only the count was double.
2. `mode_rung2()` ANDed its subtests' *exit codes* (0 = success) and then
   returned `ok ? 0 : 1`, so it exited 1 precisely when both patterns landed.
   Fixed by comparing each subtest result to 0. Confirmed before the fix:
   `./vuln rung2; echo $?` -> 1 while both subtests printed `RESULT=PASS`.

The remaining stale values were corrected in the same change: rung1's internal
expectation of `first_raw_requested=2^64-5` (the first read is the 14-byte
header, so 14 is correct) and `first_raw_bytes_used`; and `run.sh`'s grep
literals (`oob_writes=1478`, `deadbeef`/`cafebabe`, `11223344`/`55667788`)
against the source's actual two patterns.

Observed after repair, all with the digests above:

- Rung 1: `plen=-1 need=-5 datalen=14 rplen=4 guard_passed=1 close_reason=1002
  rc=-1002` (that `rc` is the WebSocket close code returned by
  `ws_read_frame`, not the process exit); `first_raw_requested=14
  first_raw_used=14 raw_calls=3 copy_calls=3 oob_writes=1464 first_oob=65536
  last_oob=66999`; C harness `RESULT=PASS`, process rc 0.
- Rung 2: pattern A writes `dedfe0e1` / `cacbcccd`, pattern B writes
  `11121314` / `55565758` at `wbuffer[0..3]` and `wbuffer[1024..1027]`; both
  subtests `RESULT=PASS`, process rc 0. Chosen bytes at chosen offsets.
- Rung 3: ASan `heap-buffer-overflow`, `WRITE of size 132146`, `0 bytes after
  a 131136-byte region`, in `memcpy` from `ws_raw_read`
  (ws_overflow.c:198) via `ws_read_frame` (:416); rc 1. Corruption confirmed.
- Rung 4: `offsetof(wsh_t, ssl)=131112`, buffer-relative input index 131104;
  `ssl before=(nil) after=0x5b3b027ff6fd` equal to the chosen target,
  `marker_called=1`, process rc 42. Untouched-`ssl` control leaves the marker
  uncalled (rc 1). Chosen-pointer control and benign marker execution are
  demonstrated in the extracted harness only.
- Controls: ordinary 8-byte frame leaves canaries unchanged with zero OOB
  writes; fixed build rejects with `rc=-1009 oob_writes=0 copy_calls=1`;
  five repeat rung-1 runs byte-identical.

Grade: rungs 1/2/3 established, rung 4 PASS **in the extracted harness with
the chosen value placed at a known offset**. Live process, WebSocket upgrade,
stock heap layout and network reachability stay UNKNOWN; the opt-in
`mod_xml_rpc` / `enable-websocket` gate remains prominent.

## Real-source loopback check, 2026-11-20 ~19:2xZ (this wake)

The witness verdict above still stands for the extracted harness. This section
adds an independently compiled check of the **unmodified upstream source** and
sharpens the boundary on the impact claim; it does not retract any harness
observation.

Compiled `ws.c` and `ws.h` copied byte-for-byte from the pinned vulnerable
parent (`ws.c` sha256 `5a07965f530296bec3840c6c8a7a29c00f34d87f76e34eacf44978ef01d84d3b`,
`ws.h` sha256 `1990aa2bf16ed22d1c8d85cde75c6226f92449d6f1290b80b9d96f8e297f897c`)
with only Abyss `TConn`/`TSession` type stand-ins and socket-backed
`ConnRead`/`ConnWrite`, and drove a crafted extended-length frame through a
real `127.0.0.1` TCP socket. Source and driver digests are in
`lab/freeswitch2shell/live/`; raw output in `logs_real_source.txt`.

- **Offset validated against the real struct.** An independent `offsetof`
  program using the exact upstream field types on this host (gcc 13.3.0) gives
  `offsetof(buffer)=8`, `offsetof(wbuffer)=65544`, `offsetof(ssl)=131112`,
  `ssl` buffer-relative `131104`, `sizeof(wsh_t)=131136` — identical to the
  harness stand-in. The chosen-offset arithmetic is not a harness artifact.
- **Real source, ASan, loopback socket:** `AddressSanitizer: negative-size-param:
  (size=-5)` in `memcpy` called from `ws_raw_read` (`ws.c:306`) via
  `ws_read_frame` (`ws.c:498`). The source pointer is inside a 4200-byte
  `TConn` allocation. Corruption is confirmed in the real function, though the
  ASan report is `negative-size-param`, not the harness's 132146-byte
  `heap-buffer-overflow`.
- **Real source, plain build:** abort `corrupted size vs. prev_size`, rc 134 —
  a reproducible crash, not a clean overwrite.
- **Fixed source, real loopback socket:** `ws.c` at fix commit `d557ca6d`
  (sha256 `8ebbe2bce71197ac4e2cdbe2e2cc43c1b5ec3acd7275b9bb4fdbf0decf0914fe`)
  rejects the same frame with `rc=-1009` (`WS_DATA_TOO_BIG`), `datalen=14`,
  no ASan report and `wsh->ssl` untouched. The real-source differential holds.

Cause, from the pinned source: `ws_raw_read` compares `r <= (issize_t)bytes`,
but `bytes` is `(size_t)need` with `need = -5`, so `(issize_t)bytes == -5` and
the comparison is false for every positive `r`. The `else` branch calls
`memcpy(..., bytes = 0xFFFFFFFFFFFFFFFB)`. The loop then computes
`need -= (issize_t)bytes = -5 - (-5) = 0`, so the giant `memcpy` runs exactly
once and faults or corrupts the heap.

Why the harness could place chosen bytes at `wsh->ssl`: its `ws_raw_read`
stand-in clamps `bytes` to the available source length before the comparison
(`ws_overflow.c:163-165`), and its `ConnRead` stand-in is a no-op over a
pre-filled in-memory stream (`ws_overflow.c:139-143`). Those two stand-in
choices turn the giant copy into a bounded, byte-faithful 131 KB write in
which every byte is sender-chosen. The real Abyss `conn.h` at this parent has
`BUFFER_SIZE 4096`, and a real `recv()` delivers at most that much. Bytes the
real `memcpy` writes past the first ~4 KB come from heap contents, not from
the sender. Collectively: chosen-pointer control at `wsh->ssl` remains
demonstrated **only in the extracted harness**; the real source path shows a
confirmed heap-corruption crash, not a controlled pointer overwrite.

A control experiment (`live/ws/ws_clamped.c`) adds only the source-side clamp
to the real source while keeping the 4096-byte chunked socket; it also fails
to place the chosen value at `wsh->ssl`. Both stand-in assumptions — clamp and
a single pre-filled stream — are required, so the harness's byte-faithful
pointer control is a property of its model, not of the upstream source.

Still UNKNOWN and not attempted this wake: a full FreeSWITCH 1.11.1
`mod_xml_rpc` + `enable-websocket` build and its `/socket` dispatch-before-auth
path. This host lacks libtool, libedit, opus, spandsp and sndfile dev packages
and has two cores; a full build is not a bounded change inside this 60-minute
wake. The opt-in configuration gate stays prominent. Full-digest evidence and
the clamped-variant isolation experiment live under
`lab/freeswitch2shell/live/`; no source outside this plant was contacted except
the pinned upstream raw files and the advisory records.
