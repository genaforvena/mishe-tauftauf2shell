# Frontier brief — FreeSWITCH mod_xml_rpc WebSocket extended-length heap over-write (Freeswitch2Shell)

**Status: admitted 2026-11-20 ~17:52Z under standing approval #6; operator
reconciliation 18:28Z below.** Frontier was cut mid-wake before it pinned
harness numbers: the old "being exercised / numbers appended" placeholder is
replaced by the reproduction section at the end of this file. A dedicated
`freeswitch2shell` charter and wake trigger unit are still owed; the two-pane
window and restorer registry entry already exist.

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

## Source-bound mechanism (read from the vulnerable parent, not inferred)

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

`ws_init()` (`ws.c:330-341`) `malloc`s `wsh_t`, zeroes it and sets
`wsh->buflen = sizeof(wsh->buffer)` = 65536.

`ws_read_frame()` (`ws.c:383-537`) reads 14 bytes into `wsh->buffer` and, for
length code `127` (`ws.c:445-459`), takes the eight length bytes at
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
   `-1 - (14 - 10) = -5`. The guard at `ws.c:485`,
   `(need + wsh->datalen) >= (issize_t)wsh->buflen`, evaluates `9 >= 65536`
   and passes. `wsh->rplen = plen - need = 4`.
2. **The copy is unbounded and byte-faithful.** The loop at `ws.c:493-505`
   calls `ws_raw_read(wsh, wsh->payload + wsh->rplen, need)`. Its third
   parameter is `size_t`, so the negative `need` becomes a huge unsigned count;
   `need -= r` only makes it more negative, so the loop runs until the input is
   exhausted (`r < 1`). Every byte after the 14-byte header is copied from
   `&buffer[14]` onward with no bound check, and the trailing NUL at
   `ws.c:521` lands at `payload + rplen`. The attacker chooses every byte at
   every offset.

The 64 KiB `buffer` and 64 KiB `wbuffer` are followed in the same allocation
by `buflen`, `datalen`, `wdatalen`, `payload`, `plen`, `rplen` and `ssl`.
`offsetof(wsh_t, ssl)` is 131112 on this host, so roughly 131098 payload bytes
place a chosen 8-byte value in `wsh->ssl`; `ws_raw_write()` (`ws.c:315-321`)
and `ws_destroy()` (`ws.c:360-368`) dereference that pointer. This is a
materially stronger primitive than the hands-off corruption claimed in the
advisory: chosen bytes at chosen offsets, including pointer-sized fields.

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

Overall the driver prints `CHECKS FAILED` only because of the stale exit-code
and literal-pattern expectations above, not because a security observation
regressed. Update `run.sh` against the current source before quoting
`ALL CHECKS PASS`; until then quote each observation with the digests above.
No live FreeSWITCH process, WebSocket upgrade or loopback network path was
tested by this reproduction.
