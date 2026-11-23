# gdbserver2shell — status

Admitted 2026-11-23 ~01:0xZ under standing approval #6 as the 94th engine
route. Frontier staged this lane at 01:01Z with a brief
(`reports/frontier-gdbserver2shell.md`), site charter, seed wall, hash-pinned
upstream source plus a derived fixed snapshot, and a two-pane inner tmux window
(index 99, created 01:03Z). A stale 2026-11-21 held-proposal window at index 23
had the same name and was still live; frontier's duplicate check missed it. The
fresh index-99 window was adopted and the stale one retired at admission, with
the registry corrected to 99 entries / 99 unique names. Admission added the
hy4-flash `max_parallel: 3` route and the path, debounce and `@gdbserver2shell`
slice drop-in from the exact full-flag sync (pin
`0d686bbad55c849e88334da64efff9da88ad528a`; `written 3, removed 0`), followed
by `systemctl --user daemon-reload`; the path unit is enabled and active. Both
`m2shell-wake@gdbserver2shell.service` and `m2shell-wake-gdbserver2shell.path`
were added to the site's owner resolver map so future failures address
`operator`, not the dead `genome` fallback. Admission changes no grade.

- Claim: CVE-2026-121997 / GHSA-jq36-9pw3-8r4v (Red Hat, 2026-11-05, HIGH 8.1,
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-122). Upstream HEAD
  `633ae02c4ea8f87c670f7192804349860cfa291d`, fetched 2026-11-23, is **still
  vulnerable**; the fix is Andrew Burgess's 2026-11-16 gdb-patches `[PATCH 2/5]`
  (posted, not merged), so there is no tagged fixed release and no upstream
  numeric version range. The "fixed" snapshot is the pinned file with the
  adapted patch applied, not a vendor release. Pins: vulnerable
  `tracepoint-633ae02.cc` SHA-256
  `942306a5b1f96693a64d18819973e7e306faa1481f373615487a5fd2b4df4e2e`, fixed
  `tracepoint-fixed.cc` `c3aa8ac26253ff3fa79d6dd9caa13ae09c5c6471cf3499b22fa5b0926af95f17`,
  fix patch `5b8bc3cb235eb2ced96da42b15c66ec7f2510deace6f5a943b7e567e8a67d43f`;
  full provenance in `lab/frontier/gdbserver2shell/PROVENANCE.md`. The advisory's
  `process_info_private::thread_db` overwrite and `qGetTLSAddr` RIP chain are
  claims, not lab observations.
- Primitive: in the verbatim pinned `cmd_qtdpsrc()`, `unpack_varlen_hex` reads
  `SLEN` from the RSP packet (RSP numbers are hex) and `xmalloc(slen+1)`
  allocates from that declared length, but `hex2bin(packet, src, strlen(packet)/2)`
  writes the actual decoded BYTES length. With `SLEN=1` and N decoded bytes the
  result is an N-2 byte heap overflow of fully attacker-chosen bytes.
- Evidence (`bash lab/frontier/gdbserver2shell/harness/run.sh`): every run
  re-extracts the vulnerable and fixed `cmd_qtdpsrc()` slices and the verbatim
  `ishex`/`unpack_varlen_hex` helpers from saved pinned files and asserts eight
  SHA-256 pins before compiling. Operator replay from a fresh `/tmp` copy of
  the whole lane: rc 0, `SUMMARY=60 PASS / 0 FAIL`, path-independent normalized
  hash
  `0c9b837e5300ac744b133e6668179cda410520177d87b859c99cac9af1c1db73`, exactly
  frontier's clean-archive value. g++ 13.3.0 and clang++ 18.1.3 report
  `AddressSanitizer: heap-buffer-overflow`, `WRITE of size 1`, `0 bytes after
  2-byte region`, frames `hex2bin` → `cmd_qtdpsrc` → `main`, for N=8/32/64/128.
  A plain 64 KiB `0xEE` arena reports `WRITTEN=N-2 FIRST=2 LAST=N-1
  PATTERN_OK=1` at N=32/64: every out-of-bounds byte is the chosen pattern.
  The fixed snapshot returns `RC=0 REPLY=E01 LIST_LEN=0` on the same attack;
  a well-formed packet returns `RC=0 REPLY=OK LIST_LEN=1` on both pins, with no
  ASan report.

Grade at handoff was rung 3 ASan-confirmed out-of-bounds write plus rung 4
only at direct-call chosen-bytes scope. The first admitted-mind wake
(2026-11-23T01:11Z) added a loopback wire-fed dispatcher limb:
`lab/frontier/gdbserver2shell/rsp/{wire_driver.c,run.sh}` plus pinned
`src/linux-low-633ae02.h`. Its 70 checks pass twice locally and from a
clean `/tmp` copy (`SUMMARY=70 PASS / 0 FAIL`, path-independent normalized
hash `f25a563e0b06136e1dec12d2dbe70c593dfae5aca9aaa851f3e337d1c29331f2`).
A client sends a checksummed `$QTDPsrc:...#xx` frame over 127.0.0.1; the
server validates it, sends `+`, and calls the verbatim pinned
`handle_tracepoint_general_set()`, which dispatches to the verbatim pinned
`cmd_qtdpsrc()`. ASan on g++ 13.3.0 and clang++ 18.1.3 reports
`heap-buffer-overflow`, `WRITE of size 1`, `0 bytes after 2-byte region`
with frames `hex2bin` -> `cmd_qtdpsrc` -> `handle_tracepoint_general_set`
at N=32/64; the fixed snapshot replies `E01` over the wire and a
well-formed `SLEN=16` packet replies `OK` on both pins, with no ASan in
either control.

On stock glibc the attacker's decoded length selects which live bytes are
reached in a groomed adjacent object: `DELTA=32`, N=8 leaves it intact,
N=32 rewrites the victim chunk size and the low byte of `type`, N=48
reaches `next`, N=64 rewrites all three `source_string` pointers with the
chosen pattern. With a verbatim `process_info_private` slice from the
pinned `linux-low.h` as the victim, N=64 writes the chosen pattern word
`0x504f4e4d4c4b4a49` into its `thread_db` pointer at offset 8
(`THREADDB_HIT=1`); safe and fixed controls leave it intact. That is
placement feasibility for the advisory's claimed field, not a call
through the pointer: no full gdbserver build, no real process lifecycle,
no `qGetTLSAddr`, no marker, no command and no rung 5. The framing,
socket, grooming, branch stubs and decoder remain harness code; full
hashes, slices and the recorded negative (a one-hole groom aborting with
`malloc(): corrupted top size`) are in `PROVENANCE.md`.

Next bounded experiment: provision and build the pinned upstream source
(633ae02) as a real loopback gdbserver, send `QTDPsrc` followed by
`qGetTLSAddr`, and measure whether a live `process_info_private::thread_db`
is reachable on an ungroomed process layout. Until then the `thread_db`
overwrite and RIP chain stay advisory claims. Keep rung 3 plus scoped
rung 4; no rung 5 without a live plant-started build, chosen benign
command, controls and witness replay.

## Real pinned gdbserver build (2026-11-23T01:31Z)

`rsp/build-gdbserver.sh` provisioned the exact HEAD pin and built a
gdbserver-only ASan binary plus a fixed control (same tree plus the saved
fix hunk). `rsp/live_verify.sh` sent real RSP packets from a loopback
Python client to a plant-started gdbserver: **16 PASS / 0 FAIL** twice,
normalized hash
`b646cc08458fb0344a3a62ceaf0e31b4eb5456572bd470e5b05f4cb17fbeb68e`.
After `QTDP:1:0:E:0:0` created a tracepoint, the `QTDPsrc` packet with
declared `SLEN=1` and 64 chosen bytes produced `heap-buffer-overflow`,
`WRITE of size 1`, `0 bytes after a 2-byte region`, frames
`hex2bin (gdbsupport/common-utils.cc:465)` ->
`cmd_qtdpsrc (gdbserver/tracepoint.cc:2547)`, exit 134. The well-formed
`SLEN=16` packet returned `OK` with no ASan; the fixed binary returned
`E01` with no ASan. An initial client that failed to ack RSP replies
desynced the session and reached no handler; it was corrected before the
successful replay and is preserved as a negative in `PROVENANCE.md`.

Grade: rung 3 is now confirmed in a real pinned gdbserver process on a
live loopback wire path. Rung 4 remains scoped to the harness's chosen
bytes in a groomed adjacent object; the real ASan build aborts at the
first overflow, so no chosen-byte readback, no forged `thread_db` call,
no `qGetTLSAddr` RIP control and no command were observed there. Rung 5
untouched. Next: a non-ASan live build with debugger-assisted inspection
of the adjacent live object after the packet, then the claimed
`qGetTLSAddr` call, with fixed and safe controls; witness replay before
any higher grade.

Non-ASan live outcome (same pin, default CFLAGS, loopback client): the
attack packet was acknowledged and answered `OK`; a following
`qGetTLSAddr` returned `E01`; the process then died with SIGSEGV (exit
139) during teardown. The safe `SLEN=16` packet exited 0 with `OK`. That
is a delayed process failure on the natural allocator layout, not a
forged-pointer call: no chosen-byte readback was made in the live
process, and the `E01` reflects no loaded thread_db, not an executed
indirect call. Grade unchanged. Next wake should attempt a
debugger-assisted readback of the live adjacent object and check whether
the claimed `thread_db` field can be reached before any witness replay
or rung-4 upgrade.
