# bacnet2shell — status

Admitted 2026-11-22 ~06:4xZ under standing approval #6 as the 72nd target
mind (76th engine route, inner window 81). Charter
`.mishe-tauftauf/charters/bacnet2shell.md`. Frontier staged the find at
commits `3fcc139`/`2e7bbdd` (brief `reports/frontier-bacnet2shell.md`); the
operator re-verified the pins and replayed the pinned harness before
admission.

- Claim: GHSA-gr74-333w-7wg8 / CVE-2026-97692, published 2026-10-04 by
  `skarg`, High 7.7 `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:H`. Affected
  `bacnet-stack <= 1.5.0` plus the audited `1.6.0-rc1`; patched 1.4.6, 1.5.2,
  1.6.1, 1.7.0. The advisory reports a trailing-MORE option walk in the
  BACnet/SC header parser and publishes a self-contained ASan/UBSan PoC.
- Brief: [reports/frontier-bacnet2shell.md](frontier-bacnet2shell.md). Pins:
  audited vulnerable commit `1068250f197c0cc78b6357374d8be5df7d94b3cc`
  (2026-06-19) and fixed master merge
  `37b081d0ebb2b92ca5297a5073850a467fa0e9c9` (2026-07-22) recorded in
  `lab/frontier/bacnet2shell/pins/PINS.txt`; fix diff PR #1435 in
  `pins/fix-97692.patch` (sha256 `ca3181b0…5041d3`). The fix adds two guards:
  reject a final region still marked MORE in
  `bvlc_sc_validate_options_headers`, and bound the decode loop with
  `i < BVLC_SC_HEADER_OPTION_MAX` in `bvlc_sc_decode_header_options`.
- Primitive: a trailing MORE bit makes the option walk advance past the
  message; with peer-supplied trailing bytes carrying chained MORE-set
  proprietary options, the walk iterates past the fixed 4-entry
  `dest_options[]` and writes decoded `vendor_id`, `option_type`, `data` and
  `data_len` through out-array pointers. On the Linux server the decode array
  is the file-static global `bsc_dm` (`bsc-socket.c:43`), so this is a BSS
  write; the WebSocket server keeps one persistent RX buffer per connection
  and resets only its length (`ports/linux/websocket-srv.c:57,509`), so the
  trailing bytes are the same unauthenticated peer's earlier frame. The
  `dest_options_num > 4` check tests the validated count (1), not the number
  of walk iterations.
- Grade at admission: **rung 3 ASan-confirmed on the real pinned decoder and
  rung 4 chosen bytes at chosen offsets in a server-shaped harness**. On the
  vulnerable decoder the vendor's exact 10-byte frame gives ASan
  `heap-buffer-overflow READ of size 1` at `bvlc-sc.c:557
  bvlc_sc_decode_option_hdr`; a 1500-byte zeroed-slack condition is benign;
  chained MORE-set slack gives ASan `WRITE of size 8` at `bvlc-sc.c:601
  bvlc_sc_decode_proprietary_option`. In the server-shaped `g_dm` harness the
  full chain gives `global-buffer-overflow` at `:601` (0 bytes past the
  432-byte global), and a bounded 11-option chain in a plain build writes
  chosen `41 42 43` at struct offsets 304/344/384/424 — a 40-byte stride
  from where `dest_options[4]` ends — with chosen `bf` markers at
  248/288/328/368/408 and decode still returning 1 silently. Every case is
  clean on fixed `37b081d0e` (`header options is truncated`, ec=147/ecl=7).
- Operator replay 2026-11-22 ~06:4xZ from the staged binaries and pinned
  trees: `harness/poc-vuln 1` reproduced the ASan READ at `bvlc-sc.c:557`;
  `poc-vuln 2` stayed benign; `poc-fixed 3` rejected cleanly;
  `harness/poc-global-plain 11` returned rc=0 with four `414243` patterns in
  the post-decode `g_dm` dump. Staged normalized hashes are in
  `lab/frontier/bacnet2shell/EVIDENCE_HASHES.txt`.
- Not claimed: live-wire pre-auth reach — source-cited by the advisory
  (`bsc_process_socket_state` / `bsc_process_srv_awaiting_request` before the
  Connect-Request handshake) but **not measured locally**; no live daemon was
  started and no wire packet was sent by the staged investigation. No pointer
  or arbitrary-address control (the destination is a fixed offset past a
  global array), no command execution, no rung 5. Witness replay is owed at
  the claimed rung-3/rung-4 scope.
- First target-mind steps: bind the pinned vulnerable BACnet/SC WebSocket
  server on 127.0.0.1, send the chained-option frame then the 10-byte frame on
  one unauthenticated connection under ASan with a fixed-build control; that
  converts the advisory's reach claim into a local measurement. Then measure
  whether a chosen write can reach a useful control-flow target before any
  rung-5 attempt. Witness replay of the staged scope is also owed.

This file is updated by the target mind; the author report is not independent
acceptance.
