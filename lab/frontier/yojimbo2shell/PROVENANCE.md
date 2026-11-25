# yojimbo2shell — pin provenance and harness scope

## Claim source (public, read-only provisioning)

- Upstream fix commit: `d3d4f3398cee5d154d22011ff7099a5d8a87d324` — "Fix remote heap
  overflow in block reassembly and bracketed IPv6 parse", Glenn Fiedler,
  2026-07-08T23:25:52Z. https://github.com/mas-bandwidth/yojimbo/commit/d3d4f3398cee5d154d22011ff7099a5d8a87d324
- Vulnerable parent: `3c6b5e85fe8da778e0ace3526e725844bb7286bf`
  (a CLAUDE.md-only commit; the channel source is unchanged from its parent).
- No CVE or GHSA was found for this fix in the GitHub Advisory Database and CNA
  feeds searched on 2026-11-25. CVE/GHSA: UNKNOWN. Fixed release/tag: UNKNOWN —
  the only confirmed fix is the master commit above.
- The commit adds a regression test that drives a hand-serialized fragment packet
  through `Connection::ProcessPacket` and reports heap-buffer-overflow under ASan
  before the fix. That packet path is post-authentication (netcode connect token
  and encryption); no pre-auth claim is made here.

## Pinned bytes (SHA-256, verified by `harness/run.sh` check 20)

All files fetched read-only from raw.githubusercontent.com at the two commits.
`src/*` hashes are recorded in `pins.sha256`:

- `src/yojimbo_reliable_ordered_channel.cpp.vuln` — parent, 783 lines. The
  verbatim sink is lines 663-782 (`ReliableOrderedChannel::ProcessPacketFragment`);
  the overflowing `memcpy` is line 716.
- `src/yojimbo_reliable_ordered_channel.cpp.fixed` — fix commit, 797 lines. The
  pre-copy guard is lines 710-722; the guarded `memcpy` is line 730.
- `src/yojimbo_channel.h.vuln`, `src/yojimbo_config.h.vuln`,
  `src/yojimbo_channel.cpp.vuln`, `src/yojimbo.h.vuln`,
  `src/yojimbo_message.h.vuln` — pinned parent headers/sources used to read the
  config helper `GetMaxFragmentsPerBlock()` (config header lines 153-160, ceil
  formula) and the fragment wire encoding (channel source lines 270-274).

## Harness scope

`harness/harness.cpp` copies the vulnerable method body verbatim (parent lines
663-782) into a stand-in class. The only injected code inside the method is the
`#ifdef YOJIMBO_FIXED` block, which is the exact upstream guard from fixed lines
710-722. Everything above the method is a minimal stand-in for yojimbo types
(`ChannelConfig`, `ReceiveBlockData`, bit array, message queue, factory).
`GetMaxFragmentsPerBlock()` is copied verbatim from the pinned config header.

- `maxBlockSize=1100`, `blockFragmentSize=500` → ceil fragment count 3, so the
  final fragment writes at offset `2*500=1000`.
- Attack: `fragmentBytes=500`, so `memcpy` writes offsets 1000..1499 into a
  1100-byte receive buffer: 400 bytes past the end.
- ASan builds allocate exactly `maxBlockSize` (`-DYOJIMBO_EXACT_ALLOCATION`) so
  the redzone begins at offset 1100.
- Plain builds allocate `maxBlockSize+512` and fill the tail with 0x5a. The
  attacker fragment carries the chosen ASCII marker `MISHE-OO` at payload
  offset 400, which lands at canary offset 300 after the copy.

## Observed evidence (`sh harness/run.sh`: 20 PASS / 0 FAIL, rc 0)

- `evidence/asan-vuln-attack.out`: ASan `heap-buffer-overflow`, `WRITE of size
  500`, frame `ReliableOrderedChannel::ProcessPacketFragment ... harness.cpp:213`,
  `0 bytes after 1100-byte region`, allocated in `ReceiveBlockData::ReceiveBlockData`
  at `harness.cpp:107`; process rc 1.
- `evidence/asan-fixed-attack.out`: rc 0, `error=1` (guard sets DESYNC), no report.
- `evidence/asan-vuln-safe.out`: `fragmentBytes=100` exactly fits; rc 0, `error=0`.
- `evidence/plain-vuln-attack.out`: `canary0=5a`, `canary300=MISHE-OO`.
- `evidence/plain-fixed-attack.out`: `canary300=ZZZZZZZZ` (0x5a bytes unchanged),
  `error=1`.

## Ceilings and unknowns

- Rung 3: ASan-confirmed heap OOB write in the pinned verbatim receive function.
- Rung 4 PARTIAL: chosen 8-byte marker at a chosen adjacent-heap offset in the
  plain build, with fixed and safe controls clean.
- No real yojimbo/netcode build, no live UDP socket, no wire packet, no pointer
  or IP control, no command execution, no rung 5. Whether a *real* peer can
  reach this config in a shipped product is UNKNOWN; the upstream regression
  test demonstrates reachability through `Connection::ProcessPacket` in a
  non-default config.
- Rendered source line numbers are harness-layer claims; the pinned file hashes
  and the verbatim guard text are authoritative.
