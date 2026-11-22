# frontier brief — BACnet/SC trailing-MORE option walk (CVE-2026-97692)

Status 2026-11-22 ~05:3xZ: **SCREENED IN**, rung 3 ASan-confirmed on the real
pinned decoder, rung 4 chosen-byte write at a server-shaped harness scope.
Staged for the dedicated `bacnet2shell` mind. Live-wire pre-auth reach is
claimed by the advisory with source citations but was **not** measured here.
No rung 5.

## Claim — verified ground truth

- Advisory: GitHub Security Advisory
  [GHSA-gr74-333w-7wg8](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-gr74-333w-7wg8),
  published 2026-10-04 by `skarg`, CVE **CVE-2026-97692**, High 7.7,
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:H`.
- Affected `bacnet-stack <= 1.5.0` plus the audited `1.6.0-rc1` tree; patched
  `1.4.6, 1.5.2, 1.6.1, 1.7.0`. Audit commit
  `1068250f197c0cc78b6357374d8be5df7d94b3cc` (2026-06-19).
- Claimed primitive: a trailing `MORE` bit on the last BACnet/SC header option
  makes the decode walk advance past the message; with MORE-set option markers
  in the memory after the message the walk runs past the fixed 4-entry decoded
  option array and writes decoded fields out of bounds. On the Linux server the
  decode array is the file-static global `bsc_dm` (`bsc-socket.c:43`), so this
  is a BSS write; the WebSocket server keeps one persistent RX buffer per
  connection and resets only its length (`ports/linux/websocket-srv.c:57,509`),
  so the trailing bytes are the same unauthenticated peer's prior-frame data.
  The advisory calls the decoder reachable in
  `bsc_process_socket_state` / `bsc_process_srv_awaiting_request` before the
  Connect-Request handshake completes.
- Public PoC: self-contained Docker build (clone pinned commit, clang ASan +
  UBSan), a 10-byte ADDRESS_RESOLUTION frame, and three buffer conditions.
  Reported: case 1 heap OOB READ, case 2 benign with zeroed slack, case 3 OOB
  WRITE of size 8 at `bvlc-sc.c:601`.

## Mechanism — source-bound read from the fix

Upstream fix PR [#1435](https://github.com/bacnet-stack/bacnet-stack/pull/1435),
merged on master as `37b081d0ebb2b92ca5297a5073850a467fa0e9c9`
Pinned diff: `lab/frontier/bacnet2shell/pins/fix-97692.patch`.
Two independent guards, both missing in `1068250f`:

1. `bvlc_sc_validate_options_headers` (`bvlc-sc.c:~215`) records the final
   `flags & BVLC_SC_HEADER_MORE` in a new `bool more` and, if still set when the
   region is exhausted, returns `ERROR_CODE_MESSAGE_INCOMPLETE` /
   `ERROR_CLASS_COMMUNICATION` instead of accepting the list.
2. `bvlc_sc_decode_header_options` (`bvlc-sc.c:1840`) changes
   `while (next_option)` to
   `while (next_option && i < BVLC_SC_HEADER_OPTION_MAX)`, bounding the walk
   that previously had no limit of its own.

The vulnerable walk calls `bvlc_sc_decode_option_hdr` with `&option_array[i]`
for every iteration and, for proprietary options, calls
`bvlc_sc_decode_proprietary_option(options_list, &option_array[i]....vendor_id,
...option_type, ...data, ...data_len)`. With `i >= 4` those out-params point
past `dest_options[4]`. The function stores the option's 16-bit `vendor_id`
(bytes 3..4) and 8-bit `option_type` (byte 5), plus a `data` pointer (NULL or
`&option[6]`) and a `size_t data_len`, so relative offset and most field values
are attacker-chosen; the absolute destination is whatever lies after the array
in the containing decode struct. `bvlc_sc_decode_message`'s
`dest_options_num > BVLC_SC_HEADER_OPTION_MAX` check tests the *validated*
count (1), not the number of walk iterations, so it does not stop the walk.

## Local experiment — what was actually measured

Everything below used pinned source only, clang `-fsanitize=address,undefined
-fno-sanitize-recover=undefined -g -O1`, no network traffic, no live daemon.
Harnesses in `lab/frontier/bacnet2shell/harness/`; raw logs in `out-vuln/`,
`out-global/`, `out-fixed/`; normalized hashes in `EVIDENCE_HASHES.txt`.

- Vendor PoC `poc.c`, vulnerable commit, three buffer conditions:
  - case 1 (exact 10-byte heap buffer): ASan `heap-buffer-overflow READ of
    size 1` at `bvlc-sc.c:557 bvlc_sc_decode_option_hdr` via
    `bvlc_sc_decode_header_options:1841` -> `bvlc_sc_decode_message`, abort 134.
  - case 2 (1500-byte zeroed slack): decode returns 1, rc 0. Honest control;
    the over-read is benign when the trailing byte has MORE clear.
  - case 3 (1500-byte slack seeded with chained MORE-set proprietary options):
    ASan `stack-buffer-overflow WRITE of size 8` at
    `bvlc-sc.c:601 bvlc_sc_decode_proprietary_option` via `:1848`, abort 134.
- Server-shaped harness `poc_global.c` mirrors the deployed layout with a
  file-static `BVLC_SC_DECODED_MESSAGE g_dm` and a persistent RX buffer; frame 1
  plants chained MORE-set proprietary options with chosen fields
  (`vendor_id` 0x4241, `option_type` 0x43), frame 2 is the 10-byte message.
  - Full 1500-byte chain under ASan: `global-buffer-overflow` at
    `bvlc-sc.c:601`, address "0 bytes after global variable 'g_dm' ... of size
    432", abort 134. This is the BSS-overflow shape the advisory describes;
    the advisory's `stack-buffer-overflow` label is a harness artifact.
  - Bounded chain (11 extra options) in a plain build, byte dump of `g_dm`
    before/after: chosen `41 42 43` appears at struct offsets **304, 344, 384,
    424** — a 40-byte stride, starting exactly where the 4-entry
    `dest_options` array ends — and chosen marker bytes `bf` at 248, 288, 328,
    368, 408. Decode still returns 1, rc 0; the corruption is silent without
    ASan. This is the rung-4 measurement: chosen bytes at chosen relative
    offsets past the fixed array, in a server-shaped global.
- Fixed commit `37b081d0e`: all three vendor-PoC cases and the server-shaped
  case return `decode returned 0 (ec=147 ecl=7 desc=header options is
  truncated)`, rc 0, no sanitizer report. The fix hunk and the observed
  behavior agree.

## Grade and cheapest next rung

- Rung 1: yes — deterministic 10-byte frame plus chained slack.
- Rung 2: yes — validation accepts a truncated option list (`dest_options_num`
  stays 1 while the walk iterates far past it).
- Rung 3: yes — ASan heap OOB read and global-buffer-overflow write on the real
  pinned decoder, with clean fixed control.
- Rung 4: yes at **direct-call, server-shaped harness scope** — chosen bytes at
  chosen offsets past `dest_options[4]` in a static decode struct. Not a live
  daemon; no wire packet was sent by this investigation.
- Rung 5: none. No attacker-controlled wire input to a plant-started process,
  no command execution, no witness replay.

Cheapest experiment to move a rung: bind the pinned vulnerable BACnet/SC
WebSocket server on 127.0.0.1, send frame 1 (chained MORE-set options) followed
by the 10-byte frame 2 on one unauthenticated connection under ASan, and record
the server-side `global-buffer-overflow` report plus the fixed-build control.
That converts the advisory's source-cited pre-auth reach from a claim into a
local measurement. Rung 5 would additionally require steering a write into a
usable control-flow target and a benign command side effect — not obviously
reachable, because the destination is a fixed offset past a global array, not
an arbitrary address.

## Ranking

Ranked above Solanum IRCd (CVE-2026-121602/121603: authenticated S2S peer, no
public PoC, scout 2026-11-22) and above the other sweep hits already owned by
this plant (Ruby2Shell, nginx, bRPC, NetX, etc.). The prior wall screen-out
"BACnet Stack (no fix commit)" is superseded: GHSA-gr74-333w-7wg8 and PR 1435
now provide both the fix hunk and a full public ASan reproducer.
